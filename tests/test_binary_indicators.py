"""Dấu hiệu ransomware: bắt được cái có thật, im lặng với phần mềm lành.

Các tệp mẫu ở đây là DỮ LIỆU KIỂM TRA, không phải mã độc: phần mã của chúng
chỉ là một lệnh `ret`, còn mọi dấu hiệu nằm trong section dữ liệu dưới dạng
chuỗi văn bản. Tệp dựng ra không chạy được và không làm gì cả - nó tồn tại
để chứng minh bộ dò nhìn thấy đúng thứ nó nói là nhìn thấy.

Nửa sau của tệp quan trọng không kém nửa đầu: phần mềm lành cũng duyệt tệp,
cũng mã hoá, cũng bị pack, cũng có entropy cao. Một bộ dò gắn cờ cả những
thứ đó thì không dùng được, nên ở đây chúng được khẳng định là PHẢI im lặng.
"""

from __future__ import annotations

import pytest

import binary_builders as B
from fortress_scan.binary import engine, scoring
from fortress_scan.binary.catalogue import SPECS
from fortress_scan.binary.model import Tier, Verdict

ONION = B.fake_onion_v3()
BITCOIN = B.fake_bitcoin_address()
BECH32 = B.fake_bech32_address()

# Ghi chú tống tiền: đủ các nhóm cụm từ mà một ghi chú thật có, viết ngắn.
RANSOM_NOTE = (
    "!!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!!\r\n"
    "To restore your files you need the private key held on our server.\r\n"
    "Price is 0.5 bitcoin. Payment in BTC only.\r\n"
    "Contact us via the Tor browser at http://%s/\r\n"
    "Do not rename or modify the encrypted files, you will lose them.\r\n"
    "You have 72 hours before the price will double and your stolen data\r\n"
    "will be published on our leak site.\r\n"
    "Your personal ID: 9F2A-77B1-C0DE-4455\r\n"
) % ONION

TARGET_EXTENSIONS = (
    ".doc .docx .xls .xlsx .ppt .pptx .pdf .txt .csv .rtf .odt .ods .jpg .jpeg .png "
    ".psd .mp3 .mp4 .avi .mkv .zip .rar .7z .sql .mdb .accdb .bak .vmdk .vhd .pst .eml"
)
SYSTEM_EXCLUSIONS = "boot.ini bootmgr ntldr ntuser.dat iconcache.db thumbs.db desktop.ini autorun.inf"
KILL_LIST = "sqlservr mysqld oracleservice veeam backupexecjobengine msexchangeis mbamservice ekrn"


def _strings_section(lines, name=".rdata"):
    body = b"\x00".join(line.encode("utf-8") for line in lines) + b"\x00"
    return B.PeSection(name, body, B.RDATA_FLAGS)


def ransom_shaped_pe(**overrides) -> bytes:
    """Tệp mang đủ các trụ của một vụ ransomware, ở dạng dữ liệu tĩnh."""
    lines = [
        RANSOM_NOTE,
        "HOW_TO_DECRYPT.txt",
        "vssadmin.exe delete shadows /all /quiet",
        "wmic.exe shadowcopy delete",
        "bcdedit /set {default} recoveryenabled no",
        "wbadmin delete catalog -quiet",
        "wevtutil.exe cl System",
        "net stop %s /y" % KILL_LIST.split()[0],
        KILL_LIST,
        TARGET_EXTENSIONS,
        SYSTEM_EXCLUSIONS,
        'cmd.exe /c ping 127.0.0.1 -n 3 > nul & del /f /q "%s"',
        "software\\microsoft\\windows\\currentversion\\run",
        BITCOIN,
        "support@tutanota.com",
    ]
    options = dict(
        sections=[
            B.PeSection(".text", b"\xc3" * 64, B.TEXT_FLAGS),
            _strings_section(lines),
        ],
        imports={
            "kernel32.dll": [
                "FindFirstFileW", "FindNextFileW", "CreateFileW", "WriteFile",
                "MoveFileExW", "DeleteFileW", "GetLogicalDriveStringsW",
            ],
            "advapi32.dll": [
                "CryptAcquireContextW", "CryptEncrypt", "CryptGenKey", "CryptImportKey",
                "OpenSCManagerW", "EnumServicesStatusExW", "ControlService",
            ],
            "mpr.dll": ["WNetOpenEnumW", "WNetEnumResourceW"],
        },
    )
    options.update(overrides)
    return B.build_pe(**options)


def benign_backup_tool_pe() -> bytes:
    """Công cụ sao lưu có mã hoá: ĐÚNG là duyệt tệp, mã hoá và ghi đè.

    Chuỗi năng lực ( FSX-C04 ) bắn ở đây là đúng, nhưng kết luận không được
    nói đây là ransomware: không có ghi chú, không phá khôi phục, không kênh
    tống tiền.
    """
    lines = [
        "Fortress Backup 3.2",
        "Backing up %d files to %s",
        "AES-256-GCM encryption enabled",
        "Restore point created",
        "net stop sqlservr /y",
        "Backup completed successfully",
    ]
    return B.build_pe(
        sections=[B.PeSection(".text", b"\xc3" * 64, B.TEXT_FLAGS), _strings_section(lines)],
        imports={
            "kernel32.dll": ["FindFirstFileW", "FindNextFileW", "CreateFileW", "MoveFileExW"],
            "advapi32.dll": ["CryptAcquireContextW", "CryptEncrypt", "CryptDeriveKey"],
        },
        resources=[(16, "1", B.version_resource({"CompanyName": "Fortress Tools", "ProductName": "Fortress Backup"}))],
        certificate=b"\x30\x82" + b"\x06\x03\x55\x04\x03\x0c\x0eFortress Tools",
    )


def benign_packed_installer_pe() -> bytes:
    """Trình cài đặt NSIS bị pack: entropy cao, bảng import nhỏ, overlay lớn.

    Đây là chân dung mà một bộ dò kém sẽ gọi là ransomware.
    """
    payload = bytes(range(256)) * 400
    return B.build_pe(
        sections=[
            B.PeSection("UPX0", b"", B.TEXT_FLAGS, virtual_size=0x20000),
            B.PeSection("UPX1", payload, B.TEXT_FLAGS),
        ],
        imports={"kernel32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualAlloc", "ExitProcess"]},
        overlay=b"\xef\xbe\xad\xdeNullsoftInst" + bytes(range(256)) * 500,
    )


# -------------------------------------------------------------- dương tính


def test_ransom_shaped_sample_reaches_a_high_verdict_with_named_pillars():
    report = engine.analyze_bytes(ransom_shaped_pe(), "mau.exe")
    found = {hit.spec.id for hit in report.hits}
    assert report.verdict is Verdict.HIGH
    assert {"FSX-T01", "FSX-C05", "FSX-C04"} <= found
    assert any("ghi chú tống tiền" in reason for reason in report.reasons)
    assert any("khôi phục" in reason for reason in report.reasons)
    # Kết luận phải nói rõ nó chắc về CÁI GÌ: về nội dung tệp, không phải về
    # việc tệp sẽ chạy thành công.
    assert "NỘI DUNG" in report.confidence


def test_every_indicator_in_the_ransom_shaped_sample_carries_its_own_evidence():
    report = engine.analyze_bytes(ransom_shaped_pe(), "mau.exe")
    assert report.hits
    for hit in report.hits:
        assert hit.evidence, "dấu hiệu %s không có bằng chứng" % hit.spec.id
        for item in hit.evidence:
            assert item.detail.strip()


def test_ransom_note_needs_several_phrase_groups_not_one_keyword():
    """Một dòng nói 'encrypted' không phải ghi chú tống tiền.

    Chính chỗ này là nơi một bộ dò theo từ khoá sẽ gắn cờ mọi tài liệu về
    bảo mật, mọi trình quản lý mật khẩu và mọi README nói về mã hoá.
    """
    weak = engine.analyze_bytes(
        ransom_shaped_pe(
            sections=[
                B.PeSection(".text", b"\xc3" * 64, B.TEXT_FLAGS),
                _strings_section(["your files are encrypted with AES-256"]),
            ]
        ),
        "mau.exe",
    )
    assert "FSX-T01" not in {hit.spec.id for hit in weak.hits}


def test_ransom_note_phrases_must_sit_close_together():
    """Các nhóm cụm từ phải nằm trong cùng một vùng văn bản.

    Rải chúng cách nhau hàng trăm KB thì đó là hai thứ khác nhau tình cờ cùng
    nằm trong một tệp, không phải một ghi chú.
    """
    note_parts = [
        "all of your files have been encrypted",
        "you need the decryption tool to restore files",
        "pay 0.5 bitcoin to purchase the key",
    ]
    filler = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod "
    spread = [note_parts[0], filler * 900, note_parts[1], filler * 900, note_parts[2]]
    report = engine.analyze_bytes(
        B.build_pe(sections=[B.PeSection(".text", b"\xc3" * 16, B.TEXT_FLAGS), _strings_section(spread)]),
        "mau.exe",
    )
    assert "FSX-T01" not in {hit.spec.id for hit in report.hits}

    together = engine.analyze_bytes(
        B.build_pe(
            sections=[B.PeSection(".text", b"\xc3" * 16, B.TEXT_FLAGS), _strings_section(note_parts)]
        ),
        "mau.exe",
    )
    assert "FSX-T01" in {hit.spec.id for hit in together.hits}


@pytest.mark.parametrize(
    "command,indicator",
    [
        ("vssadmin.exe delete shadows /all /quiet", "FSX-C05"),
        ("wmic shadowcopy delete", "FSX-C05"),
        ("bcdedit /set {default} recoveryenabled No", "FSX-C05"),
        ("wbadmin delete systemstatebackup -keepversions:0", "FSX-C05"),
        ("vim-cmd vmsvc/snapshot.removeall 12", "FSX-C05"),
        ("tmutil deletelocalsnapshots /", "FSX-C05"),
        ("reagentc.exe /disable", "FSX-C05"),
        ("wevtutil cl Security", "FSX-C11"),
        ("fsutil usn deletejournal /D C:", "FSX-C11"),
        ("Set-MpPreference -DisableRealtimeMonitoring $true", "FSX-C12"),
        ("Add-MpPreference -ExclusionPath C:\\", "FSX-C12"),
        ("netsh advfirewall set allprofiles state off", "FSX-C12"),
        ("bcdedit /set {default} safeboot network", "FSX-C12"),
        ("cipher /w:C", "FSX-C15"),
        ("\\\\.\\PhysicalDrive0", "FSX-C16"),
    ],
)
def test_single_destructive_command_is_recognised(command, indicator):
    report = engine.analyze_bytes(
        B.build_pe(sections=[B.PeSection(".text", b"\xc3" * 16, B.TEXT_FLAGS), _strings_section([command])]),
        "mau.exe",
    )
    assert indicator in {hit.spec.id for hit in report.hits}, command


def test_recovery_inhibition_alone_is_suspicious_but_not_a_ransomware_verdict():
    """Một lệnh vssadmin không đủ để gọi là ransomware.

    Nó nặng, nên tệp phải được gắn cờ; nhưng script dọn dẹp của quản trị viên
    cũng có đúng một dòng như vậy.
    """
    report = engine.analyze_bytes(
        B.build_pe(
            sections=[
                B.PeSection(".text", b"\xc3" * 16, B.TEXT_FLAGS),
                _strings_section(["vssadmin delete shadows /all"]),
            ]
        ),
        "mau.exe",
    )
    assert report.verdict is Verdict.SUSPICIOUS
    assert report.verdict < Verdict.LIKELY


def test_onion_and_wallet_addresses_must_pass_their_checksum():
    """Địa chỉ .onion v3 và ví Bitcoin đều có checksum.

    Không kiểm checksum thì mọi chuỗi base32 dài 56 ký tự ( hash, khoá, id )
    đều thành 'hạ tầng tống tiền'.
    """
    good = engine.analyze_bytes(
        B.build_pe(sections=[B.PeSection(".text", b"\xc3" * 16, B.TEXT_FLAGS), _strings_section([ONION, BITCOIN, BECH32])]),
        "mau.exe",
    )
    kinds = {ioc.kind for ioc in good.iocs}
    assert {"onion", "bitcoin"} <= kinds
    assert {hit.spec.id for hit in good.hits} >= {"FSX-T03", "FSX-T04"}

    broken_onion = "a" + ONION[1:]
    broken_wallet = BITCOIN[:-1] + ("A" if BITCOIN[-1] != "A" else "B")
    noisy = engine.analyze_bytes(
        B.build_pe(
            sections=[
                B.PeSection(".text", b"\xc3" * 16, B.TEXT_FLAGS),
                _strings_section([broken_onion, broken_wallet, "a" * 56 + ".onion"]),
            ]
        ),
        "mau.exe",
    )
    assert not [ioc for ioc in noisy.iocs if ioc.kind in ("bitcoin", "onion")]
    assert "FSX-T04" not in {hit.spec.id for hit in noisy.hits}


def test_extension_and_exclusion_lists_need_a_real_list_not_one_name():
    """Một đuôi tệp lẻ không phải danh sách mục tiêu."""
    single = engine.analyze_bytes(
        B.build_pe(sections=[B.PeSection(".text", b"\xc3" * 16, B.TEXT_FLAGS), _strings_section([".docx", ".pdf", "thumbs.db"])]),
        "mau.exe",
    )
    found = {hit.spec.id for hit in single.hits}
    assert "FSX-T06" not in found and "FSX-T07" not in found

    full = engine.analyze_bytes(
        B.build_pe(
            sections=[
                B.PeSection(".text", b"\xc3" * 16, B.TEXT_FLAGS),
                _strings_section([TARGET_EXTENSIONS, SYSTEM_EXCLUSIONS]),
            ]
        ),
        "mau.exe",
    )
    found = {hit.spec.id for hit in full.hits}
    assert {"FSX-T06", "FSX-T07"} <= found


def test_kill_list_needs_several_names_across_more_than_one_group():
    """Trình cài đặt Office đóng Word, Excel, Outlook: một nhóm, không gắn cờ.

    Ransomware dừng cùng lúc CSDL, sao lưu và phần mềm bảo mật: nhiều nhóm.
    """
    office = engine.analyze_bytes(
        B.build_pe(
            sections=[
                B.PeSection(".text", b"\xc3" * 16, B.TEXT_FLAGS),
                _strings_section(["winword excel powerpnt outlook msaccess onenote visio"]),
            ]
        ),
        "mau.exe",
    )
    assert "FSX-C06" not in {hit.spec.id for hit in office.hits}

    spread = engine.analyze_bytes(
        B.build_pe(
            sections=[B.PeSection(".text", b"\xc3" * 16, B.TEXT_FLAGS), _strings_section([KILL_LIST])]
        ),
        "mau.exe",
    )
    assert "FSX-C06" in {hit.spec.id for hit in spread.hits}


def test_esxi_variant_is_recognised_from_paths_and_disk_extensions():
    lines = [
        "/vmfs/volumes",
        "esxcli vm process kill --type=force --world-id=%s",
        "vim-cmd vmsvc/getallvms",
        "encrypting .vmdk .vmx .vmsn .vswp",
    ]
    data = B.build_elf(
        sections=[
            B.ElfSection(".text", b"\x90" * 32, flags=B.SHF_ALLOC | B.SHF_EXEC),
            B.ElfSection(".rodata", b"\x00".join(line.encode() for line in lines), flags=B.SHF_ALLOC),
        ],
        imported=["opendir", "readdir", "rename"],
    )
    report = engine.analyze_bytes(data, "svc-stat")
    assert "FSX-C14" in {hit.spec.id for hit in report.hits}


def test_dotnet_sample_is_scored_from_metadata_identifiers_and_literals():
    """Ransomware viết bằng C# không có bảng import nói lên điều gì.

    Năng lực của nó nằm trong tên kiểu .NET, còn ghi chú nằm trong heap #US.
    """
    metadata = B.dotnet_metadata(
        identifiers=[
            "RijndaelManaged", "CreateEncryptor", "CryptoStream", "RSACryptoServiceProvider",
            "FromXmlString", "EnumerateFiles", "GetDirectories", "WriteAllBytes", "MoveTo",
        ],
        user_strings=[RANSOM_NOTE, "vssadmin delete shadows /all /quiet", TARGET_EXTENSIONS],
    )
    report = engine.analyze_bytes(B.build_pe(clr=True, clr_metadata=metadata), "mau.exe")
    found = {hit.spec.id for hit in report.hits}
    assert {"FSX-T01", "FSX-C05", "FSX-C04", "FSX-C03"} <= found
    assert report.verdict >= Verdict.LIKELY
    assert any("không dịch ngược IL" in note for note in report.limitations)


def test_powershell_script_with_an_encoded_payload_is_scored_on_the_decoded_text():
    """Payload base64 phải được tính như văn bản đã giải mã.

    Nếu không, mọi script chỉ cần một lớp -EncodedCommand là vô hình.
    """
    import base64

    inner = (
        "vssadmin.exe delete shadows /all /quiet; "
        "Get-ChildItem -Recurse C:\\ | ForEach-Object { $_.FullName }; "
        "Set-Content -Path HOW_TO_DECRYPT.txt -Value 'all your files have been encrypted, "
        "pay 0.5 bitcoin to restore your files'"
    )
    encoded = base64.b64encode(inner.encode("utf-16-le")).decode("ascii")
    report = engine.analyze_bytes(
        ("powershell.exe -nop -w hidden -EncodedCommand %s\r\n" % encoded).encode("utf-8"),
        "loader.ps1",
    )
    found = {hit.spec.id for hit in report.hits}
    assert {"FSX-S13", "FSX-C05"} <= found
    assert report.verdict >= Verdict.SUSPICIOUS
    assert any("đã giải mã" in note.location or "dòng" in note.location
               for hit in report.hits for note in hit.evidence)


def test_batch_script_caret_escapes_do_not_hide_the_command():
    report = engine.analyze_bytes(
        b"@echo off\r\nv^s^sadmin de^lete sh^adows /all /quiet\r\n", "x.bat"
    )
    assert "FSX-C05" in {hit.spec.id for hit in report.hits}


def test_embedded_public_key_blobs_are_reported():
    import struct

    blob = b"\x06\x02\x00\x00\x00\xa4\x00\x00RSA1" + struct.pack("<II", 2048, 65537)
    report = engine.analyze_bytes(
        B.build_pe(sections=[B.PeSection(".text", b"\xc3" * 16, B.TEXT_FLAGS), B.PeSection(".rdata", blob, B.RDATA_FLAGS)]),
        "mau.exe",
    )
    hit = next(hit for hit in report.hits if hit.spec.id == "FSX-T08")
    assert any("RSA 2048" in item.detail for item in hit.evidence)


def test_aes_and_chacha_constants_are_found_without_any_import():
    from fortress_scan.binary.detectors import AES_SBOX_PREFIX, CHACHA_SIGMA

    body = b"\x00" * 64 + AES_SBOX_PREFIX + b"\x00" * 64 + CHACHA_SIGMA[0]
    report = engine.analyze_bytes(
        B.build_pe(sections=[B.PeSection(".text", b"\xc3" * 16, B.TEXT_FLAGS), B.PeSection(".rdata", body, B.RDATA_FLAGS)]),
        "mau.exe",
    )
    hit = next(hit for hit in report.hits if hit.spec.id == "FSX-T09")
    assert len(hit.evidence) >= 2


# ---------------------------------------------------------------- âm tính


def test_a_bare_hello_world_binary_produces_no_indicator_at_all():
    for data, name in (
        (B.build_pe(imports={"kernel32.dll": ["ExitProcess", "WriteConsoleW"]}), "hello.exe"),
        (B.build_elf(imported=["puts", "exit"], needed=["libc.so.6"]), "hello"),
        (B.build_macho(imported=["puts", "exit"]), "hello"),
    ):
        report = engine.analyze_bytes(data, name)
        assert report.verdict is Verdict.NONE, (name, [hit.spec.id for hit in report.hits])
        assert report.score < 10


def test_a_signed_backup_tool_is_flagged_but_never_called_ransomware():
    report = engine.analyze_bytes(benign_backup_tool_pe(), "backup.exe")
    found = {hit.spec.id for hit in report.hits}
    assert "FSX-C04" in found, "chuỗi năng lực có thật, phải nói ra"
    assert not {"FSX-T01", "FSX-C05", "FSX-T03", "FSX-T04"} & found
    assert report.verdict <= Verdict.SUSPICIOUS
    assert report.parsed.signature.present
    assert "ransomware" not in report.confidence.lower()


def test_a_packed_installer_is_not_pushed_past_a_low_verdict_by_entropy_alone():
    """Entropy và packer KHÔNG BAO GIỜ được tự đẩy kết luận lên.

    Trình cài đặt lành và ransomware thật có cùng chân dung entropy; chỉ nội
    dung và năng lực mới phân biệt được hai thứ đó.
    """
    report = engine.analyze_bytes(benign_packed_installer_pe(), "setup.exe")
    found = {hit.spec.id for hit in report.hits}
    assert {"FSX-S01", "FSX-S02"} <= found, "vẫn phải nói là tệp đã bị pack"
    assert report.verdict <= Verdict.LOW, [hit.spec.id for hit in report.hits]
    # Và phải nói thẳng rằng kết quả này có thể đánh giá thấp mức nguy hiểm.
    assert "hạn chế" in report.confidence


def test_an_installer_overlay_is_named_instead_of_being_counted_as_a_payload():
    report = engine.analyze_bytes(benign_packed_installer_pe(), "setup.exe")
    assert "FSX-S05" not in {hit.spec.id for hit in report.hits}
    assert any("NSIS" in note for note in report.notes)


def test_an_unexplained_high_entropy_overlay_is_still_reported():
    report = engine.analyze_bytes(
        B.build_pe(overlay=bytes(range(256)) * 400),
        "loader.exe",
    )
    assert "FSX-S05" in {hit.spec.id for hit in report.hits}


def test_a_security_document_full_of_ransomware_words_is_not_an_executable_verdict():
    """Chính tài liệu phòng thủ là thứ hay bị bắt oan nhất.

    Một tệp .txt không phải tệp thực thi, nên nó không được đi vào kết luận
    như một tệp thực thi.
    """
    report = engine.analyze_bytes(RANSOM_NOTE.encode("utf-8"), "huong-dan-ung-cuu.txt")
    assert report.parsed.family == "unknown"
    assert any("Không nhận ra định dạng" in note for note in report.limitations)


def test_scanning_the_tool_s_own_catalogue_does_not_trip_the_tool():
    """Danh mục dấu hiệu của chính công cụ chứa đủ mọi cụm từ nhạy cảm.

    Nếu quét nó mà ra kết luận cao thì ngưỡng đang đặt theo từ khoá, không
    theo chuỗi hành vi.
    """
    from pathlib import Path

    import fortress_scan.binary.catalogue as catalogue
    import fortress_scan.binary.detectors as detectors

    for module in (catalogue, detectors):
        source = Path(module.__file__).read_bytes()
        report = engine.analyze_bytes(source, Path(module.__file__).name)
        assert report.verdict <= Verdict.SUSPICIOUS, module.__name__
        # Và phải nói rõ vì sao bị chặn trần, chứ không im lặng hạ kết luận.
        assert "CHẶN TRẦN" in report.confidence
        assert any("chặn trần" in note for note in report.notes)
        # Dấu hiệu vẫn còn nguyên kèm bằng chứng: người đọc tự đánh giá lại được.
        assert any(hit.spec.id == "FSX-C05" for hit in report.hits)


def test_the_reference_guard_never_applies_to_a_compiled_executable():
    """Phép chặn trần CHỈ dành cho script và tệp văn bản.

    Một tệp PE đã biên dịch mang sẵn chuỗi "T1486" không được nhờ thế mà nhẹ
    đi: ở đó chuỗi không phải mã nguồn của bộ quy tắc nào.
    """
    attack_ids = " ".join("T14%02d" % index for index in range(80, 95))
    markers = "MITRE ATT&CK detection rule_id sigma yara false positive remediation"
    report = engine.analyze_bytes(
        ransom_shaped_pe(
            sections=[
                B.PeSection(".text", b"\xc3" * 64, B.TEXT_FLAGS),
                _strings_section(
                    [
                        RANSOM_NOTE,
                        "vssadmin.exe delete shadows /all /quiet",
                        attack_ids,
                        markers,
                    ]
                ),
            ]
        ),
        "mau.exe",
    )
    assert report.verdict is Verdict.HIGH
    assert "CHẶN TRẦN" not in report.confidence


def test_the_reference_guard_leaves_a_real_malicious_script_alone():
    """Một script độc hại thật không tự dán nhãn ATT&CK và không phải regex.

    Nếu phép chặn trần bắt cả script này thì nó đã quá rộng và phải sửa.
    """
    body = "\r\n".join(
        [
            "vssadmin.exe delete shadows /all /quiet",
            "wevtutil.exe cl System",
            "Get-ChildItem -Recurse C:\\Users | ForEach-Object { $_.FullName }",
            "Set-Content HOW_TO_DECRYPT.txt 'all of your files have been encrypted, "
            "pay 0.5 bitcoin to restore your files, contact us via the tor browser'",
        ]
    )
    report = engine.analyze_bytes(body.encode("utf-8"), "run.ps1")
    assert report.verdict >= Verdict.LIKELY
    assert "CHẶN TRẦN" not in report.confidence


# ---------------------------------------------------------------- chấm điểm


def test_verdict_needs_pillars_and_cannot_be_reached_by_stacking_context():
    """Cộng dồn dấu hiệu bối cảnh không bao giờ thành kết luận cao.

    Đây là tính chất quan trọng nhất của phần chấm điểm: một tệp lành có thể
    có rất nhiều dấu hiệu bối cảnh.
    """
    from fortress_scan.binary.model import IndicatorHit

    context_only = [
        IndicatorHit(SPECS[name], [], Tier.CONTEXT)
        for name in ("FSX-C01", "FSX-C02", "FSX-C03", "FSX-S01", "FSX-S02", "FSX-S05", "FSX-S06", "FSX-T09")
    ]
    verdict, pillars = scoring.verdict_for(context_only)
    assert verdict <= Verdict.LOW
    assert pillars == {}


def test_score_stays_inside_the_band_of_its_verdict():
    """Điểm chỉ để sắp thứ tự trong cùng một kết luận, không được nhảy băng."""
    from fortress_scan.binary.model import IndicatorHit

    everything = [IndicatorHit(spec, [], None) for spec in SPECS.values()]
    verdict, _ = scoring.verdict_for(everything)
    score = scoring.score_for(verdict, everything)
    low, high = scoring.BANDS[verdict]
    assert low <= score <= high


def test_every_catalogue_entry_is_complete_and_honest():
    """Mỗi dấu hiệu phải nói được: vì sao đáng ngờ, khi nào là lành, và sửa sao.

    Thiếu phần 'khi nào là lành' thì báo cáo biến mọi dấu hiệu thành phán
    quyết, và đó là cách một công cụ như thế này gây hại.
    """
    for spec in SPECS.values():
        assert spec.id.startswith("FSX-")
        assert spec.category in ("structural", "capability", "content")
        assert spec.title and spec.rationale and spec.benign and spec.remediation
        assert len(spec.benign) > 20, spec.id
        assert len(spec.remediation) > 20, spec.id
        assert 1 <= spec.weight <= 10
        for technique in spec.attack:
            assert technique.startswith("T") and technique[1:].replace(".", "").isdigit()


def test_indicator_ids_are_unique_and_grouped_by_prefix():
    for indicator_id, spec in SPECS.items():
        assert indicator_id == spec.id
        prefix = {"structural": "FSX-S", "capability": "FSX-C", "content": "FSX-T"}[spec.category]
        assert indicator_id.startswith(prefix)


def test_only_strong_indicators_can_stand_alone():
    """Dấu hiệu bậc 'mạnh' là dấu hiệu gần như chỉ ransomware mới có.

    Danh sách đó phải ngắn và phải có lý do; để nó phình ra là cách kết luận
    cao dần trở nên vô nghĩa.
    """
    strong = [spec.id for spec in SPECS.values() if spec.tier is Tier.STRONG]
    assert set(strong) == {"FSX-C05", "FSX-T01"}


def test_guidance_matches_the_severity_of_the_verdict():
    for verdict in Verdict:
        steps = scoring.guidance_for(verdict)
        assert steps
        if verdict is Verdict.HIGH:
            joined = " ".join(steps).lower()
            assert "cô lập" in joined
            assert "không trả tiền chuộc" in joined
            assert "đừng tắt nguồn" in joined
        if verdict is Verdict.NONE:
            assert not any("cô lập" in step.lower() for step in steps)


def test_a_clean_report_never_claims_the_file_is_safe():
    report = engine.analyze_bytes(B.build_pe(), "hello.exe")
    assert report.verdict is Verdict.NONE
    assert "không phải chứng nhận an toàn" in report.confidence
    assert report.limitations


# ------------------------------------------------- bộ mẫu dựng tay, mọi định dạng

# Mỗi mục ở đây là một tệp DỮ LIỆU dựng bằng tay, mang đủ các trụ của một vụ
# ransomware ở đúng chỗ mà định dạng đó lưu nội dung: chuỗi trong section PE,
# heap #US của .NET, hằng trong constant pool của Java, mục lục PyInstaller,
# văn bản script. Không mục nào chứa mã làm được việc gì.
#
# Con số "bắt được bao nhiêu trên bao nhiêu" trong README lấy từ đây, nên bảng
# này và README không thể lệch nhau.


def _esxi_lines():
    return [
        "/vmfs/volumes",
        "esxcli vm process kill --type=force --world-id=%s",
        "vim-cmd vmsvc/getallvms",
        "vim-cmd vmsvc/snapshot.removeall %s",
        ".vmdk .vmx .vmsn .vswp",
        RANSOM_NOTE,
    ]


def _encoded_powershell():
    import base64

    inner = (
        "vssadmin.exe delete shadows /all /quiet; wevtutil.exe cl System; "
        "Get-ChildItem -Recurse C:\\ | ForEach-Object { $_.FullName }; "
        "Set-Content HOW_TO_DECRYPT.txt 'all of your files have been encrypted, pay 0.5 "
        "bitcoin to restore your files, contact us via the tor browser, do not rename them'"
    )
    encoded = base64.b64encode(inner.encode("utf-16-le")).decode("ascii")
    return ("powershell.exe -nop -w hidden -EncodedCommand %s\r\n" % encoded).encode("utf-8")


def _rodata_elf(lines, **kwargs):
    return B.build_elf(
        sections=[
            B.ElfSection(".text", b"\x90" * 64, flags=B.SHF_ALLOC | B.SHF_EXEC),
            B.ElfSection(".rodata", b"\x00".join(line.encode("utf-8") for line in lines), flags=B.SHF_ALLOC),
        ],
        **kwargs
    )


SHAPED_SAMPLES = {
    "pe-native": ("mau.exe", ransom_shaped_pe()),
    "pe-dotnet": (
        "mau.exe",
        B.build_pe(
            clr=True,
            clr_metadata=B.dotnet_metadata(
                identifiers=[
                    "RijndaelManaged", "CreateEncryptor", "CryptoStream", "RSACryptoServiceProvider",
                    "FromXmlString", "EnumerateFiles", "GetDirectories", "WriteAllBytes", "MoveTo",
                ],
                user_strings=[RANSOM_NOTE, "vssadmin delete shadows /all /quiet", TARGET_EXTENSIONS, SYSTEM_EXCLUSIONS],
            ),
        ),
    ),
    "pe-packed": (
        "mau.exe",
        B.build_pe(
            sections=[
                B.PeSection("UPX0", b"", B.TEXT_FLAGS, virtual_size=0x20000),
                B.PeSection("UPX1", bytes(range(256)) * 400, B.TEXT_FLAGS),
                _strings_section([RANSOM_NOTE, "vssadmin.exe delete shadows /all /quiet", KILL_LIST]),
            ],
            imports={"kernel32.dll": ["LoadLibraryA", "GetProcAddress"]},
        ),
    ),
    "pe-pyinstaller": (
        "mau.exe",
        B.build_pe(
            overlay=B.pyinstaller_overlay(
                {
                    "locker": (
                        "NOTE = '''%s'''\nEXTENSIONS = '%s'\n"
                        "COMMAND = 'vssadmin delete shadows /all /quiet'\n" % (RANSOM_NOTE, TARGET_EXTENSIONS)
                    ).encode("utf-8")
                }
            )
        ),
    ),
    "powershell-encoded": ("loader.ps1", _encoded_powershell()),
    "batch-escaped": (
        "run.bat",
        (
            "@echo off\r\nv^s^sadmin de^lete sh^adows /all /quiet\r\nwevtutil cl System\r\n"
            "echo all of your files have been encrypted, pay 0.5 bitcoin to restore your files "
            "> HOW_TO_DECRYPT.txt\r\n"
            "echo contact us via the tor browser, do not rename them >> HOW_TO_DECRYPT.txt\r\n"
        ).encode("utf-8"),
    ),
    "vbscript": (
        "run.vbs",
        (
            'Set fso = CreateObject("Scripting.FileSystemObject")\r\n'
            'fso.GetFolder("C:\\").SubFolders\r\n'
            'WshShell.Run "vssadmin delete shadows /all /quiet"\r\n'
            'f.Write "all your files have been encrypted. pay 0.5 bitcoin. contact us via the tor '
            'browser. your personal ID: 9F2A77B1"\r\n'
        ).encode("utf-8"),
    ),
    "elf-linux": (
        "locker",
        _rodata_elf(
            [RANSOM_NOTE, TARGET_EXTENSIONS, BITCOIN, "shred -u %s", "crontab -e"],
            imported=["opendir", "readdir", "rename", "EVP_EncryptUpdate", "crypto_box_seal"],
        ),
    ),
    "elf-esxi": (
        "encrypt",
        _rodata_elf(
            _esxi_lines(),
            imported=["opendir", "readdir", "rename", "EVP_EncryptInit_ex", "RSA_public_encrypt"],
        ),
    ),
    "macho": (
        "locker",
        B.build_macho(
            segments=(
                (
                    "__TEXT",
                    (
                        ("__text", b"\xc3" * 32),
                        (
                            "__cstring",
                            b"\x00".join(
                                line.encode("utf-8")
                                for line in [RANSOM_NOTE, TARGET_EXTENSIONS, "tmutil deletelocalsnapshots /", BITCOIN]
                            ),
                        ),
                    ),
                    0x5,
                ),
            ),
            imported=["opendir", "readdir", "rename", "CCCrypt", "SecKeyCreateEncryptedData"],
        ),
    ),
    "jar": (
        "locker.jar",
        B.build_jar(
            {
                "META-INF/MANIFEST.MF": b"Main-Class: Locker\n",
                "Locker.class": B.build_class(
                    [
                        "javax/crypto/Cipher", "getInstance", "AES/CBC/PKCS5Padding",
                        "java/nio/file/Files", "walkFileTree", "renameTo",
                        "javax/crypto/spec/SecretKeySpec",
                    ]
                ),
                "note.txt": RANSOM_NOTE.encode("utf-8"),
                "ext.txt": TARGET_EXTENSIONS.encode("utf-8"),
                "cmd.txt": b"vssadmin delete shadows /all /quiet\nwevtutil cl System\n",
            }
        ),
    ),
}


def test_the_shaped_corpus_covers_every_format_the_subsystem_claims():
    """Bảng mẫu phải phủ đủ các họ định dạng, kẻo con số trong README nói quá."""
    families = {engine.identify(data, name)[0] for name, data in SHAPED_SAMPLES.values()}
    assert families == {"pe", "elf", "macho", "zip", "script"}
    assert len(SHAPED_SAMPLES) == 11


@pytest.mark.parametrize("key", sorted(SHAPED_SAMPLES))
def test_every_shaped_sample_reaches_at_least_a_likely_verdict(key):
    name, data = SHAPED_SAMPLES[key]
    report = engine.analyze_bytes(data, name)
    assert report.verdict >= Verdict.LIKELY, (key, report.verdict, [hit.spec.id for hit in report.hits])
    assert report.reasons
    assert report.strong_hits, "kết luận cao phải dựa trên ít nhất một dấu hiệu bậc mạnh"
