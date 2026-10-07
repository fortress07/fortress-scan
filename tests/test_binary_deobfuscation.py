"""Chuỗi bị che bằng XOR một byte phải được giải ra, và việc giải phải KHÔNG
đẻ ra báo nhầm.

Bài đo dẫn tới phần này: lấy đúng một tệp mang đủ dấu hiệu rồi XOR riêng vùng
chuỗi của nó, kết luận tụt từ 100 điểm xuống 20; XOR kèm bảng import rút gọn
thì tụt hẳn về "sạch". Chín dấu hiệu nội dung chết cùng lúc vì một phép toán
tầm thường. Những bài dưới đây khoá lại cả hai chiều: chiều bắt lại được, và
chiều KHÔNG được bịa ra khoá ở nơi không có khoá nào.

Không có mẫu mã độc nào ở đây. Mọi tệp đều dựng từng byte từ bộ builder lành,
rồi XOR bằng một byte do bài kiểm tra tự chọn.
"""

from __future__ import annotations

import random

import pytest

import binary_builders as B
import test_binary_indicators as T
from fortress_scan.binary import deobfuscate, engine
from fortress_scan.binary.model import Tier, Verdict

KEYS = [0x01, 0x20, 0x5A, 0x7F, 0xFF]

FULL_IMPORTS = {
    "kernel32.dll": [
        "FindFirstFileW", "FindNextFileW", "CreateFileW", "WriteFile",
        "MoveFileExW", "DeleteFileW", "GetLogicalDriveStringsW",
    ],
    "advapi32.dll": [
        "CryptAcquireContextW", "CryptEncrypt", "CryptGenKey", "CryptImportKey",
        "OpenSCManagerW", "ControlService",
    ],
}
# Bảng import của một tệp đã pack: ba hàm vừa đủ để tự nạp phần còn lại.
STUB_IMPORTS = {"kernel32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualAlloc"]}

LINES = [
    T.RANSOM_NOTE,
    "HOW_TO_DECRYPT.txt",
    "vssadmin.exe delete shadows /all /quiet",
    "wmic.exe shadowcopy delete",
    "bcdedit /set {default} recoveryenabled no",
    "wbadmin delete catalog -quiet",
    "wevtutil.exe cl System",
    T.KILL_LIST,
    T.TARGET_EXTENSIONS,
    T.SYSTEM_EXCLUSIONS,
    T.BITCOIN,
    "support@tutanota.com",
]
BLOB = b"\x00".join(line.encode("utf-8") for line in LINES) + b"\x00"


def xor(blob: bytes, key: int) -> bytes:
    return blob.translate(bytes(index ^ key for index in range(256)))


def hidden_pe(key: int, imports=None) -> bytes:
    """Đúng tệp của bộ fixture, chỉ khác vùng chuỗi đã bị XOR."""
    return B.build_pe(
        sections=[
            B.PeSection(".text", b"\xc3" * 64, B.TEXT_FLAGS),
            B.PeSection(".rdata", xor(BLOB, key), B.RDATA_FLAGS),
        ],
        imports=imports or FULL_IMPORTS,
    )


def ids(report) -> set:
    return {hit.spec.id for hit in report.hits}


# --------------------------------------------------------------------- bắt lại


@pytest.mark.parametrize("key", KEYS)
def test_a_single_byte_xor_no_longer_hides_the_whole_file(key):
    report = engine.analyze_bytes(hidden_pe(key), "mau.exe")
    assert report.verdict >= Verdict.LIKELY, (key, report.verdict, report.score)
    assert "FSX-T01" in ids(report), "ghi chú tống tiền phải lộ ra sau khi giải"
    assert "FSX-C05" in ids(report), "lệnh phá khôi phục phải lộ ra sau khi giải"


@pytest.mark.parametrize("key", KEYS)
def test_hiding_the_strings_is_itself_reported(key):
    """Giấu tên lệnh của hệ điều hành là một dấu hiệu, không phải chuyện bình thường."""
    report = engine.analyze_bytes(hidden_pe(key), "mau.exe")
    hit = next(h for h in report.hits if h.spec.id == "FSX-S15")
    assert hit.tier >= Tier.SUSPICIOUS
    assert any("0x%02x" % key in item.detail for item in hit.evidence), [
        item.detail for item in hit.evidence
    ]


def test_a_stub_import_table_does_not_save_the_file_either():
    """Ca tệ nhất trước khi vá: giấu chuỗi CỘNG rút gọn import ra kết luận 'sạch'."""
    report = engine.analyze_bytes(hidden_pe(0x5A, STUB_IMPORTS), "mau.exe")
    assert report.verdict >= Verdict.LIKELY, (report.verdict, report.score)


def test_the_recovered_strings_say_where_they_came_from():
    """Báo cáo không được trình chuỗi đã giải như thể nó nằm lộ thiên."""
    report = engine.analyze_bytes(hidden_pe(0x5A), "mau.exe")
    labels = {label for _, _, label in report.pool.iter_strings()}
    assert any(label.startswith("xor:0x5a") for label in labels), sorted(labels)


def test_a_wide_anchor_is_found_too():
    """API Windows hay ở dạng UTF-16, nên mỏ neo rộng phải tự đứng được."""
    body = "CryptEncrypt".encode("utf-16-le") + b"\x00" * 8
    data = xor(body * 4, 0x33)
    assert [key for key, _, _ in deobfuscate.find_keys(data)] == [0x33]


# ------------------------------------------------------- không được bịa ra khoá


def test_random_data_never_yields_a_key():
    """Mỏ neo mười byte: trúng ngẫu nhiên là chuyện không xảy ra, và đây là bằng chứng."""
    noise = random.Random(20261006).randbytes(4 << 20)
    assert deobfuscate.find_keys(noise) == []


def test_a_benign_tool_is_not_given_a_hidden_layer():
    report = engine.analyze_bytes(T.benign_backup_tool_pe(), "sao-luu.exe")
    assert "FSX-S15" not in ids(report)
    assert report.verdict < Verdict.SUSPICIOUS


def test_plaintext_is_not_reported_as_hidden():
    """Khoá 0 chỉ là chuỗi lộ thiên; báo nó là 'bị che' thì sai sự thật."""
    data = B.build_pe(
        sections=[
            B.PeSection(".text", b"\xc3" * 64, B.TEXT_FLAGS),
            B.PeSection(".rdata", BLOB, B.RDATA_FLAGS),
        ],
        imports=FULL_IMPORTS,
    )
    assert deobfuscate.find_keys(data) == []
    assert "FSX-S15" not in ids(engine.analyze_bytes(data, "mau.exe"))


def test_recovery_cannot_rescue_a_file_that_hides_everything():
    """Giới hạn thật, và nó phải nằm trong bộ test chứ không chỉ trong README.

    Pack thật sự thì chuỗi không còn tồn tại dưới dạng XOR một byte nữa, nên
    phép này không cứu được. Kết luận phải ở lại mức thấp, không được tự tin
    lên chỉ vì đã có thêm một bộ giải."""
    data = B.build_pe(
        sections=[
            B.PeSection("UPX0", b"", B.TEXT_FLAGS, virtual_size=0x20000),
            B.PeSection("UPX1", bytes(range(256)) * 600, B.TEXT_FLAGS),
        ],
        imports=STUB_IMPORTS,
    )
    report = engine.analyze_bytes(data, "mau.exe")
    assert report.verdict <= Verdict.LOW, (report.verdict, report.score)
    assert "FSX-S15" not in ids(report)


# ------------------------------------------------------------------- có trần


def test_the_scan_is_bounded_on_a_huge_file():
    """Một tệp lớn không được kéo cả lượt quét đi theo."""
    filler = bytes(random.Random(7).randbytes(1 << 20))
    data = filler * 48 + xor(b"vssadmin delete shadows", 0x11)
    # Mỏ neo nằm NGOÀI trần, nên không tìm thấy: đó là hành vi đúng, có chủ ý.
    assert deobfuscate.find_keys(data) == []


def test_at_most_a_few_keys_are_followed():
    pieces = [xor(b"vssadmin delete shadows /all", key) + b"\x00" * 32 for key in range(1, 20)]
    found = deobfuscate.find_keys(b"".join(pieces))
    assert 0 < len(found) <= deobfuscate.MAX_KEYS


def test_a_key_split_across_two_chunks_is_still_found():
    """Mỏ neo nằm vắt qua ranh giới khúc là chỗ dễ bỏ sót nhất."""
    anchor = xor(b"shadowcopy delete", 0x44)
    head = bytes(deobfuscate.CHUNK - 8)
    assert [key for key, _, _ in deobfuscate.find_keys(head + anchor)] == [0x44]


def test_two_hidden_spots_far_apart_are_both_recovered():
    """Bảng chuỗi bị che có thể nằm rải, nên tệp nhỏ được giải nguyên vẹn."""
    gap = bytes(300 << 10)
    data = xor(b"vssadmin delete shadows", 0x2B) + gap + xor(b"HOW_TO_DECRYPT.txt", 0x2B)
    assert len(data) < deobfuscate.FULL_DECODE_LIMIT
    key, start, blob, _ = deobfuscate.recover(data)[0]
    assert key == 0x2B and start == 0
    assert b"vssadmin delete shadows" in blob and b"HOW_TO_DECRYPT.txt" in blob


def test_a_large_file_only_gets_a_window():
    """Trên tệp lớn phải có trần, kẻo một tệp là đủ kéo cả lượt quét đi theo."""
    anchor = xor(b"vssadmin delete shadows", 0x2B)
    data = bytes(9 << 20) + anchor + bytes(1 << 20)
    assert len(data) > deobfuscate.FULL_DECODE_LIMIT
    _, _, blob, _ = deobfuscate.recover(data)[0]
    assert len(blob) <= deobfuscate.WINDOW
    assert b"vssadmin delete shadows" in blob


def test_truncated_and_tiny_inputs_do_not_raise():
    for size in range(0, 24):
        assert deobfuscate.find_keys(bytes(size)) == []
    assert deobfuscate.recover(b"") == []
