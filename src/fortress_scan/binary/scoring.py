"""Từ danh sách dấu hiệu ra một kết luận có lý do.

Kết luận KHÔNG phải tổng điểm vượt ngưỡng. Nó dựa trên các "trụ" độc lập của
một vụ ransomware: ghi chú tống tiền, phá khả năng khôi phục, năng lực mã hoá
hàng loạt, kênh tống tiền, và bước chuẩn bị ( dừng dịch vụ, xoá log, danh
sách mục tiêu ). Một trình cài đặt bị pack và một ransomware đều có entropy
cao, nên entropy và packer KHÔNG BAO GIỜ tự đẩy kết luận lên quá mức "cần
lưu ý": chúng chỉ làm giảm độ tin của một kết quả sạch.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from .model import IndicatorHit, Parsed, Tier, Verdict

PREPARATION = ("FSX-C06", "FSX-C10", "FSX-C11", "FSX-C12", "FSX-C15", "FSX-T06", "FSX-T07")
VISIBILITY_LIMITERS = ("FSX-S01", "FSX-S02", "FSX-S04", "FSX-S08", "FSX-S12", "FSX-S13")

BANDS: Dict[Verdict, Tuple[int, int]] = {
    Verdict.NONE: (0, 9),
    Verdict.LOW: (10, 29),
    Verdict.SUSPICIOUS: (30, 59),
    Verdict.LIKELY: (60, 84),
    Verdict.HIGH: (85, 100),
}


def _by_id(hits: List[IndicatorHit]) -> Dict[str, IndicatorHit]:
    return {hit.spec.id: hit for hit in hits}


def pillars(hits: List[IndicatorHit]) -> Dict[str, List[str]]:
    """Các trụ đã đứng, mỗi trụ kèm mã dấu hiệu dựng nên nó."""
    index = _by_id(hits)
    result: Dict[str, List[str]] = {}

    def add(name: str, indicator: str) -> None:
        result.setdefault(name, []).append(indicator)

    note = index.get("FSX-T01")
    if note is not None and note.tier is Tier.STRONG:
        add("note", "FSX-T01")
    elif note is not None:
        add("note-fragment", "FSX-T01")
    if "FSX-T02" in index:
        add("note-fragment", "FSX-T02")
    if "FSX-C05" in index:
        add("inhibit", "FSX-C05")
    for indicator in ("FSX-C04", "FSX-C14", "FSX-C16"):
        hit = index.get(indicator)
        if hit is not None and hit.tier >= Tier.SUSPICIOUS:
            add("impact", indicator)
    for indicator in ("FSX-T03", "FSX-T04"):
        hit = index.get(indicator)
        if hit is not None and hit.tier >= Tier.SUSPICIOUS:
            add("extort", indicator)
    if "FSX-T05" in index and "extort" in result:
        add("extort", "FSX-T05")
    preparation = [indicator for indicator in PREPARATION if indicator in index]
    if len(preparation) >= 2:
        result["prep"] = preparation
    return result


_PILLAR_TEXT = {
    "note": "có văn bản ghi chú tống tiền đầy đủ",
    "note-fragment": "có tên tệp hoặc mảnh văn bản giống ghi chú tống tiền",
    "inhibit": "có lệnh xoá bản sao bóng / vô hiệu hoá khôi phục",
    "impact": "có đủ năng lực mã hoá / phá dữ liệu hàng loạt",
    "extort": "có kênh nhận tiền chuộc đã kiểm checksum ( .onion v3, ví Bitcoin )",
    "prep": "có từ hai bước chuẩn bị trở lên ( dừng dịch vụ, xoá log, danh sách mục tiêu ... )",
}


def verdict_for(hits: List[IndicatorHit]) -> Tuple[Verdict, Dict[str, List[str]]]:
    found = pillars(hits)
    strong = sum(1 for name in ("note", "inhibit") if name in found)
    others = sum(1 for name in ("note-fragment", "impact", "extort", "prep") if name in found)
    serious_weight = sum(hit.spec.weight for hit in hits if hit.tier >= Tier.SUSPICIOUS and hit.spec.category != "structural")
    if (strong == 2 and others >= 1) or (strong == 1 and others >= 3):
        return Verdict.HIGH, found
    if strong >= 1 and strong + others >= 2:
        return Verdict.LIKELY, found
    if strong == 1 or others >= 2 or (others >= 1 and serious_weight >= 7) or serious_weight >= 10:
        return Verdict.SUSPICIOUS, found
    # Một hai dấu hiệu bối cảnh ( duyệt thư mục, có AES ) là chân dung của gần
    # như mọi chương trình; gắn nhãn "cần lưu ý" cho chúng chỉ làm loãng nhãn.
    context_weight = sum(hit.spec.weight for hit in hits if hit.tier is Tier.CONTEXT)
    if any(hit.tier >= Tier.SUSPICIOUS for hit in hits) or context_weight >= 4:
        return Verdict.LOW, found
    return Verdict.NONE, found


def score_for(verdict: Verdict, hits: List[IndicatorHit]) -> int:
    low, high = BANDS[verdict]
    raw = sum(hit.spec.weight * (2 if hit.tier is Tier.STRONG else 1) for hit in hits)
    return low + min(high - low, raw)


def visibility_limited(hits: List[IndicatorHit], parsed: Parsed) -> List[str]:
    index = _by_id(hits)
    limits = [indicator for indicator in VISIBILITY_LIMITERS if indicator in index]
    if parsed.has_trait("no-section-headers"):
        limits.append("không có bảng section")
    if parsed.has_trait("encrypted-members"):
        limits.append("mục trong kho được mã hoá")
    if parsed.has_trait("fairplay-encrypted"):
        limits.append("mã được mã hoá FairPlay")
    return limits


def confidence_for(verdict: Verdict, found: Dict[str, List[str]], limited: List[str]) -> str:
    if verdict is Verdict.HIGH:
        return (
            "Cao về NỘI DUNG: tệp thực sự chứa %s. Phân tích tĩnh không chứng minh tệp sẽ chạy "
            "thành công trên máy của anh em, nhưng hãy xử lý nó như ransomware ngay."
            % "; ".join(_PILLAR_TEXT[name] for name in found)
        )
    if verdict is Verdict.LIKELY:
        return (
            "Trung bình - cao: %s. Đủ để cách ly tệp; nên xác nhận hành vi trong sandbox cách ly."
            % "; ".join(_PILLAR_TEXT[name] for name in found)
        )
    if verdict is Verdict.SUSPICIOUS:
        reason = "; ".join(_PILLAR_TEXT[name] for name in found) or "có dấu hiệu đáng ngờ nhưng chưa thành chuỗi"
        return "Trung bình: %s. Chưa đủ để kết luận là ransomware; cần phân tích thêm." % reason
    if verdict is Verdict.LOW:
        if limited:
            return (
                "Thấp, VÀ tầm nhìn bị hạn chế: tệp bị pack / làm rối nên phân tích tĩnh có thể "
                "không thấy năng lực thật. Kết quả này có thể đánh giá thấp mức nguy hiểm."
            )
        return "Thấp: chỉ có dấu hiệu bối cảnh vốn rất phổ biến ở phần mềm lành."
    if limited:
        return (
            "Không thấy dấu hiệu, nhưng tầm nhìn bị hạn chế ( %s ); đây KHÔNG phải xác nhận an toàn."
            % ", ".join(limited)
        )
    return "Không thấy dấu hiệu nào. Đây là bằng chứng tốt, không phải chứng nhận an toàn."


_GUIDANCE = {
    Verdict.HIGH: (
        "Nếu tệp ĐÃ chạy: cô lập máy khỏi mạng ngay ( rút cáp / tắt Wi-Fi / cách ly bằng EDR ), "
        "nhưng ĐỪNG tắt nguồn: bộ nhớ có thể còn khoá mã hoá.",
        "Thu ảnh bộ nhớ và bản sao tệp trước khi dọn dẹp; ghi lại thời điểm.",
        "Chặn hash SHA-256 và các IOC trong báo cáo trên EDR / tường lửa / proxy toàn tổ chức.",
        "Tìm cùng hash và các tên tệp ghi chú trên những máy khác; vô hiệu hoá tài khoản bị dùng để chạy tệp.",
        "Kiểm tra bản sao lưu ngoại tuyến còn nguyên vẹn trước khi khôi phục; không khôi phục lên máy chưa làm sạch.",
        "Không trả tiền chuộc. Tra công cụ giải mã miễn phí của dự án No More Ransom và báo cơ quan chức năng.",
    ),
    Verdict.LIKELY: (
        "Cách ly tệp ( quarantine ), không chạy thử trên máy thật.",
        "Nếu tệp đã chạy: xử lý như sự cố ransomware ( cô lập máy, không tắt nguồn, thu bằng chứng ).",
        "Xác nhận hành vi trong sandbox cách ly mạng; chặn hash trên EDR trong lúc chờ.",
        "Tìm cùng hash trên các máy khác.",
    ),
    Verdict.SUSPICIOUS: (
        "Không chạy tệp trên máy thật; giữ trong khu cách ly.",
        "Phân tích động trong sandbox cách ly mạng để xem nó thực sự làm gì.",
        "Xác minh nguồn gốc: ai tải về, từ đâu, có chữ ký của nhà phát hành không.",
    ),
    Verdict.LOW: (
        "Xác minh nguồn gốc và chữ ký số của tệp trước khi tin dùng.",
        "Nếu tệp bị pack và không rõ nguồn gốc, phân tích động trước khi cho phép chạy.",
    ),
    Verdict.NONE: (
        "Không có hành động bắt buộc. Vẫn chỉ chạy phần mềm từ nguồn tin cậy và giữ sao lưu ngoại tuyến.",
    ),
}


def guidance_for(verdict: Verdict) -> List[str]:
    return list(_GUIDANCE[verdict])


def pillar_text(name: str) -> str:
    return _PILLAR_TEXT[name]
