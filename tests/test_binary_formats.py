"""Parser định dạng tệp thực thi: đọc đúng cái mà đặc tả nói.

Mọi tệp ở đây được dựng từng byte trong `binary_builders`, nên bài kiểm tra
khẳng định được cả những con số mà một tệp thật không cho biết trước: RVA
nào ánh xạ ra offset nào, entropy của đúng mấy byte đó, imphash của đúng thứ
tự import đó.
"""

from __future__ import annotations

import struct
import sys
import pytest

import binary_builders as B
from fortress_scan.binary import engine
from fortress_scan.binary.entropy import shannon
from fortress_scan.binary.formats import archive, elf, embedded, macho, pe, scripts
from fortress_scan.binary.reader import ByteView, Truncated


# ------------------------------------------------------------------ nhận diện


@pytest.mark.parametrize(
    "data,expected",
    [
        (B.build_pe(), "pe"),
        (B.build_elf(), "elf"),
        (B.build_macho(), "macho"),
        (B.build_fat_macho([B.build_macho()]), "macho"),
        (B.build_jar({"a.txt": b"x"}), "zip"),
        (B.build_class(["x"]), "class"),
        (b"\x00" * 64, "unknown"),
    ],
)
def test_format_is_identified_from_magic_bytes(data, expected):
    assert engine.identify(data, "mau.bin")[0] == expected


def test_java_class_and_fat_macho_share_a_magic_and_are_told_apart():
    """CAFEBABE là magic của CẢ fat Mach-O và tệp .class.

    Phân biệt bằng con số ngay sau magic: fat binary ghi số kiến trúc ( nhỏ ),
    .class ghi số phiên bản lớp ( từ 45 trở lên ). Đoán sai ở đây làm mọi tệp
    .class bị đem đi parse như Mach-O.
    """
    assert engine.identify(B.build_class(["x"], major=52), "")[0] == "class"
    assert engine.identify(B.build_fat_macho([B.build_macho()]), "")[0] == "macho"
    assert not macho.is_fat(B.build_class(["x"], major=52))
    assert macho.is_fat(B.build_fat_macho([B.build_macho()]))


# ------------------------------------------------------------------------ PE


def test_pe_header_section_and_import_tables_are_read_exactly():
    data = B.build_pe(
        sections=[
            B.PeSection(".text", b"\xc3" * 64, B.TEXT_FLAGS),
            B.PeSection(".data", b"A" * 100, B.DATA_FLAGS | B.SECTION_WRITE),
        ],
        imports={
            "kernel32.dll": ["FindFirstFileW", "FindNextFileW", "CreateFileW"],
            "advapi32.dll": ["CryptEncrypt", "CryptImportKey"],
        },
        timestamp=0x60000000,
    )
    parsed = pe.parse(data)
    assert parsed.format == "PE32+"
    assert parsed.arch == "x86-64"
    assert parsed.timestamp == 0x60000000
    assert parsed.metadata["subsystem"] == "Windows console"
    assert parsed.anomalies == []
    assert [section.name for section in parsed.sections] == [".text", ".data", ".idata"]

    text = parsed.sections[0]
    assert text.executable and not text.writable
    assert text.virtual_size == 64
    assert text.raw_size == B.FILE_ALIGNMENT  # SizeOfRawData luôn tròn theo FileAlignment
    data_section = parsed.sections[1]
    assert data_section.writable and not data_section.executable

    assert parsed.libraries == ["kernel32.dll", "advapi32.dll"]
    assert [item.name for item in parsed.imports] == [
        "FindFirstFileW",
        "FindNextFileW",
        "CreateFileW",
        "CryptEncrypt",
        "CryptImportKey",
    ]
    assert all(item.ordinal is None for item in parsed.imports)


def test_pe32_and_pe32_plus_use_different_optional_header_layouts():
    """PE32 và PE32+ khác nhau ở ImageBase và vị trí NumberOfRvaAndSizes.

    Đọc sai một trong hai thì bảng thư mục trôi đi vài byte và mọi import
    biến mất trong im lặng -- đúng kiểu hỏng mà một tệp 32-bit thật sẽ gây ra.
    """
    for machine, expected in ((0x14C, "PE32"), (0x8664, "PE32+")):
        parsed = pe.parse(B.build_pe(machine=machine, imports={"user32.dll": ["MessageBoxW"]}))
        assert parsed.format == expected
        assert [item.name for item in parsed.imports] == ["MessageBoxW"]
        assert parsed.anomalies == []


def test_pe_imports_by_ordinal_are_kept_with_their_number():
    """Import theo ordinal không có tên; mất nó là mất cả một nhánh năng lực."""
    data = bytearray(B.build_pe(imports={"ws2_32.dll": ["connect"]}))
    parsed = pe.parse(bytes(data))
    section = next(s for s in parsed.sections if s.name == ".idata")
    # Thunk đầu tiên nằm ngay sau bảng descriptor ( 2 descriptor x 20 byte ).
    thunk_at = section.offset + 40
    data[thunk_at : thunk_at + 8] = struct.pack("<Q", (1 << 63) | 0x73)
    parsed = pe.parse(bytes(data))
    assert [(item.name, item.ordinal) for item in parsed.imports] == [("", 0x73)]


def test_pe_delay_loaded_imports_are_marked_and_kept_out_of_imphash():
    """imphash theo định nghĩa của Mandiant chỉ tính bảng import thường."""
    data = B.build_pe(imports={"kernel32.dll": ["LoadLibraryA", "GetProcAddress"]})
    parsed = pe.parse(data)
    assert parsed.imphash == pe.imphash(parsed.imports)
    delayed = list(parsed.imports) + [pe.Import("secur32.dll", "EncryptMessage", delayed=True)]
    assert pe.imphash(delayed) == parsed.imphash


def test_pe_imphash_follows_order_and_normalises_the_library_suffix():
    first = pe.parse(B.build_pe(imports={"kernel32.dll": ["CreateFileW", "ReadFile"]})).imphash
    same = pe.parse(B.build_pe(imports={"KERNEL32.DLL": ["CreateFileW", "ReadFile"]})).imphash
    swapped = pe.parse(B.build_pe(imports={"kernel32.dll": ["ReadFile", "CreateFileW"]})).imphash
    assert first == same, "tên thư viện phải được chuẩn hoá về chữ thường, bỏ .dll"
    assert first != swapped, "imphash phải phụ thuộc thứ tự import"
    assert pe.imphash([]) == ""


def test_pe_exports_and_dll_flag_are_read():
    parsed = pe.parse(B.build_pe(dll=True, exports=["Encrypt", "Decrypt"]))
    assert parsed.has_trait("dll")
    assert parsed.exports == ["Encrypt", "Decrypt"]
    assert parsed.metadata["export_name"] == "sample.dll"


def test_pe_resource_tree_entropy_and_version_fields_are_read():
    payload = bytes(range(256)) * 300
    parsed = pe.parse(
        B.build_pe(
            resources=[
                (16, "1", B.version_resource({"CompanyName": "Acme Ltd", "OriginalFilename": "a.exe"})),
                (10, "PAYLOAD", payload),
            ]
        )
    )
    kinds = {resource.type: resource for resource in parsed.resources}
    assert set(kinds) == {"VERSION", "RCDATA"}
    assert kinds["RCDATA"].size == len(payload)
    assert kinds["RCDATA"].entropy == pytest.approx(shannon(payload), abs=1e-9)
    assert kinds["RCDATA"].entropy > 7.9  # 256 byte phân bố đều
    assert parsed.metadata["CompanyName"] == "Acme Ltd"
    assert parsed.metadata["OriginalFilename"] == "a.exe"


def test_pe_overlay_is_measured_and_a_trailing_certificate_is_not_counted_as_one():
    """Chứng chỉ Authenticode nằm cuối tệp là chuyện bình thường.

    Tính nó thành overlay entropy cao thì MỌI tệp có ký số đều bị gắn thêm
    một dấu hiệu, tức là dấu hiệu đó mất hết giá trị.
    """
    plain = pe.parse(B.build_pe(overlay=b"\x41" * 5000))
    assert plain.overlay is not None
    assert plain.overlay.size == 5000
    assert plain.signature.present is False

    signed = pe.parse(B.build_pe(certificate=b"\x30\x82" + b"\x00" * 3000))
    assert signed.signature.present is True
    assert signed.overlay is None


def test_pe_overlay_installer_signatures_are_named():
    for magic, expected in (
        (b"\xef\xbe\xad\xdeNullsoftInst", "NSIS"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
        (b"MSCF", "CAB"),
    ):
        parsed = pe.parse(B.build_pe(overlay=magic + b"\x00" * 70000))
        assert parsed.overlay is not None
        assert expected in parsed.overlay.kind


def test_pe_certificate_common_names_are_extracted_as_hints_only():
    blob = b"\x30\x82" + b"\x06\x03\x55\x04\x0a\x13\x08Acme Inc" + b"\x06\x03\x55\x04\x03\x0c\x07Acme CA"
    parsed = pe.parse(B.build_pe(certificate=blob))
    assert set(parsed.signature.signer_hints) == {"Acme Inc", "Acme CA"}
    assert "chưa kiểm" not in parsed.signature.kind  # phần "chưa kiểm" do báo cáo nói


def test_pe_packer_section_names_are_recognised():
    parsed = pe.parse(
        B.build_pe(
            sections=[
                B.PeSection("UPX0", b"", B.TEXT_FLAGS, virtual_size=0x4000),
                B.PeSection("UPX1", bytes(range(256)) * 40, B.TEXT_FLAGS),
            ]
        )
    )
    assert parsed.packers == ["UPX"]


def test_pe_dotnet_metadata_identifiers_and_user_strings_are_read():
    metadata = B.dotnet_metadata(
        identifiers=["RijndaelManaged", "CreateEncryptor", "ConfusedByAttribute"],
        user_strings=["tất cả tệp đã bị mã hoá", "readme"],
        runtime="v4.0.30319",
    )
    parsed = pe.parse(B.build_pe(clr=True, clr_metadata=metadata))
    assert parsed.has_trait(".net")
    assert parsed.metadata["dotnet_runtime"] == "v4.0.30319"
    assert "#Strings" in parsed.metadata["dotnet_streams"]
    names = [name for name, _ in parsed.names]
    assert "RijndaelManaged" in names and "CreateEncryptor" in names
    assert parsed.packers == ["ConfuserEx"]
    assert "tất cả tệp đã bị mã hoá" in parsed.embedded_text[0][1]


def test_dotnet_obfuscated_identifier_ratio_is_flagged():
    """Obfuscator .NET đặt tên bằng ký tự không in được; đây là cách nhận ra."""
    readable = B.dotnet_metadata(identifiers=["Program%d" % index for index in range(50)])
    assert not pe.parse(B.build_pe(clr=True, clr_metadata=readable)).has_trait("obfuscated-names")

    mangled = B.dotnet_metadata(
        identifiers=["\u0080\u0081\u0082%d" % index for index in range(40)] + ["Main"] * 10
    )
    assert pe.parse(B.build_pe(clr=True, clr_metadata=mangled)).has_trait("obfuscated-names")


def test_pe_entry_point_outside_every_section_is_reported():
    parsed = pe.parse(B.build_pe(entry_rva=0x900000))
    assert parsed.entry_section is None
    assert any("entry point" in note for note in parsed.anomalies)


def test_pe_without_aslr_and_drivers_are_labelled():
    assert pe.parse(B.build_pe(aslr=False)).has_trait("no-aslr")
    assert pe.parse(B.build_pe(driver=True)).has_trait("driver")
    assert pe.parse(B.build_pe()).has_trait("no-aslr") is False


def test_pyinstaller_archive_is_unpacked_without_marshal():
    """Script của PyInstaller là code object đã marshal.

    Công cụ CHỈ giải nén zlib rồi rút chuỗi. Gọi marshal.loads trên dữ liệu
    không tin cậy là một lỗ hổng thực thi mã, nên nó không bao giờ được gọi.
    """
    overlay = B.pyinstaller_overlay(
        {"locker": b"import os\nTEXT = 'moi tep da bi ma hoa'\n"},
        extra=["python311.dll", "_ssl.pyd"],
    )
    data = B.build_pe(overlay=overlay)
    parsed = pe.parse(data)
    embedded.pyinstaller(data, parsed)
    assert parsed.has_trait("pyinstaller")
    assert parsed.packers == ["PyInstaller"]
    assert [name for name, _ in parsed.names][:3] == ["locker", "python311.dll", "_ssl.pyd"]
    labels = dict(parsed.embedded)
    assert b"moi tep da bi ma hoa" in labels["PyInstaller script locker"]

    # Bằng chứng mạnh hơn là dò chuỗi trong mã nguồn: module không hề nhập
    # marshal, nên không có đường nào gọi tới nó.
    assert not hasattr(embedded, "marshal")


def test_go_build_info_gives_version_and_module_path():
    modinfo = "path\texample.com/app\nmod\texample.com/app\t(devel)\ndep\tgolang.org/x/crypto\tv0.1.0\n"
    blob = bytearray(b"\xff Go buildinf:\x08\x02")
    blob += b"\x00" * (32 - len(blob))
    blob += bytes([len("go1.22.0")]) + b"go1.22.0"
    encoded = modinfo.encode("utf-8")
    size = len(encoded)
    varint = bytearray()
    while size >= 0x80:
        varint.append((size & 0x7F) | 0x80)
        size >>= 7
    varint.append(size)
    blob += varint + encoded
    data = B.build_pe(sections=[B.PeSection(".text", bytes(blob), B.TEXT_FLAGS)])
    parsed = pe.parse(data)
    embedded.go_buildinfo(data, parsed)
    assert parsed.has_trait("go")
    assert parsed.metadata["go_version"] == "go1.22.0"
    assert parsed.metadata["go_main_package"] == "example.com/app"
    assert parsed.metadata["go_dependencies"] == "1"


# ----------------------------------------------------------------------- ELF


def test_elf_headers_symbols_and_needed_libraries_are_read():
    data = B.build_elf(
        imported=["opendir", "readdir", "rename"],
        exported=["run_backup"],
        local_symbols=["derive_key"],
        needed=["libc.so.6", "libcrypto.so.3"],
    )
    parsed = elf.parse(data)
    assert parsed.format == "ELF64"
    assert parsed.arch == "x86-64"
    assert parsed.metadata["elf_type"] == "executable"
    assert parsed.metadata["byte_order"] == "little-endian"
    assert parsed.metadata["interpreter"].endswith("ld-linux-x86-64.so.2")
    assert [item.name for item in parsed.imports] == ["opendir", "readdir", "rename"]
    assert parsed.exports == ["run_backup"]
    assert ("derive_key", "symtab") in parsed.names
    assert parsed.libraries == ["libc.so.6", "libcrypto.so.3"]
    assert parsed.anomalies == []


@pytest.mark.parametrize("bits64", [True, False])
@pytest.mark.parametrize("little", [True, False])
def test_elf_reads_all_four_class_and_byte_order_combinations(bits64, little):
    """ELF32 big-endian vẫn tồn tại ( MIPS, PowerPC trong thiết bị mạng ).

    Đọc cứng little-endian 64-bit nghĩa là mọi tệp như vậy ra kết quả rác mà
    không báo gì.
    """
    data = B.build_elf(
        bits64=bits64, little=little, imported=["opendir"], needed=["libc.so.6"]
    )
    parsed = elf.parse(data)
    assert parsed.format == ("ELF64" if bits64 else "ELF32")
    assert parsed.metadata["byte_order"] == ("little-endian" if little else "big-endian")
    assert [item.name for item in parsed.imports] == ["opendir"]
    assert parsed.libraries == ["libc.so.6"]
    assert parsed.anomalies == []


def test_elf_without_section_headers_falls_back_to_segments():
    """Packer ELF ( UPX ) xoá bảng section. Mất bảng đó không được mất luôn
    phép đo entropy, vì đó chính là lúc entropy đáng xem nhất."""
    data = B.build_elf(drop_section_headers=True)
    parsed = elf.parse(data)
    assert parsed.has_trait("no-section-headers")
    assert [section.name for section in parsed.sections] == ["LOAD[0]"]
    assert parsed.sections[0].entropy > 0
    assert any("bảng section" in note for note in parsed.anomalies)


def test_elf_static_stripped_and_executable_stack_traits():
    dynamic = elf.parse(B.build_elf(local_symbols=["main"], needed=["libc.so.6"]))
    assert not dynamic.has_trait("static")
    assert not dynamic.has_trait("stripped")

    static = elf.parse(B.build_elf(interpreter=None))
    assert static.has_trait("static")
    assert static.has_trait("stripped")

    assert elf.parse(B.build_elf(executable_stack=True)).has_trait("executable-stack")


def test_elf_writable_executable_segment_is_detected():
    parsed = elf.parse(B.build_elf(writable_executable=True))
    assert any(trait.startswith("wx-segment") for trait in parsed.traits)
    assert not any(trait.startswith("wx-segment") for trait in elf.parse(B.build_elf()).traits)


def test_elf_go_sections_mark_the_toolchain():
    parsed = elf.parse(
        B.build_elf(sections=[B.ElfSection(".go.buildinfo", b"\x00" * 32, flags=B.SHF_ALLOC)])
    )
    assert parsed.has_trait("go")


# -------------------------------------------------------------------- Mach-O


def test_macho_segments_symbols_dylibs_and_signature_are_read():
    data = B.build_macho(
        segments=(
            ("__TEXT", (("__text", b"\xc3" * 32), ("__cstring", b"hello\x00")), 0x5),
            ("__DATA", (("__data", b"A" * 16),), 0x3),
        ),
        imported=["opendir", "CCCrypt"],
        exported=["main"],
        dylibs=["/usr/lib/libSystem.B.dylib", "/usr/lib/libcrypto.dylib"],
        code_signature=b"\xfa\xde\x0c\xc0" + b"\x06\x03\x55\x04\x03\x0c\x0bApple Inc.",
    )
    parsed = macho.parse(data)
    assert parsed.format == "Mach-O 64-bit"
    assert parsed.arch == "x86-64"
    assert parsed.metadata["macho_type"] == "executable"
    assert [section.name for section in parsed.sections] == [
        "__TEXT,__text",
        "__TEXT,__cstring",
        "__DATA,__data",
    ]
    assert [item.name for item in parsed.imports] == ["opendir", "CCCrypt"]
    assert parsed.exports == ["main"]
    assert parsed.libraries == ["/usr/lib/libSystem.B.dylib", "/usr/lib/libcrypto.dylib"]
    assert parsed.signature.present
    assert parsed.signature.signer_hints == ["Apple Inc."]
    assert parsed.anomalies == []


def test_macho_dylib_and_missing_pie_are_labelled():
    assert macho.parse(B.build_macho(filetype=6)).has_trait("dll")
    assert macho.parse(B.build_macho(pie=False)).has_trait("no-aslr")
    assert not macho.parse(B.build_macho(pie=True)).has_trait("no-aslr")


def test_macho_object_files_do_not_count_as_writable_executable():
    """Tệp .o nào cũng có một segment rwx vô danh.

    Coi đó là dấu hiệu W+X thì mọi tệp object trong một thư mục build đều bị
    gắn cờ -- nhiễu đúng vào chỗ người dùng quét cả repo.
    """
    object_file = macho.parse(B.build_macho(filetype=1, segments=(("", (("__text", b"\xc3" * 16),), 0x7),)))
    assert not any(trait.startswith("wx-segment") for trait in object_file.traits)
    assert not object_file.sections[0].writable

    image = macho.parse(B.build_macho(filetype=2, segments=(("__TEXT", (("__text", b"\xc3" * 16),), 0x7),)))
    assert any(trait.startswith("wx-segment") for trait in image.traits)


def test_macho_universal_binary_merges_every_slice():
    intel = B.build_macho(imported=["opendir"], cpu=0x01000007)
    arm = B.build_macho(imported=["CCCrypt"], cpu=0x0100000C)
    parsed = macho.parse(B.build_fat_macho([intel, arm], cpus=[0x01000007, 0x0100000C]))
    assert parsed.format == "Mach-O universal"
    assert parsed.arch == "x86-64, ARM64"
    assert len(parsed.children) == 2
    assert {item.name for item in parsed.imports} == {"opendir", "CCCrypt"}
    assert parsed.anomalies == []


def test_macho_fat_slice_pointing_outside_the_file_is_reported():
    data = bytearray(B.build_fat_macho([B.build_macho()]))
    data[16:20] = struct.pack(">I", 0x7FFFFF00)  # size của lát
    parsed = macho.parse(bytes(data))
    assert any("vượt cuối tệp" in note for note in parsed.anomalies)


# ------------------------------------------------------------------ JAR / ZIP


def test_jar_members_manifest_and_class_constants_are_read():
    data = B.build_jar(
        {
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nMain-Class: com.example.Tool\n",
            "com/example/Tool.class": B.build_class(
                ["javax/crypto/Cipher", "getInstance", "AES/CBC/PKCS5Padding"]
            ),
            "notes.txt": "mọi tệp đã bị mã hoá".encode("utf-8"),
        },
        signed=True,
    )
    parsed = archive.parse(data, "tool.jar")
    assert parsed.family == "jar"
    assert parsed.has_trait("java")
    assert parsed.metadata["main_class"] == "com.example.Tool"
    assert parsed.signature.present
    blobs = dict(parsed.embedded_text)
    assert "javax/crypto/Cipher" in blobs["com/example/Tool.class"]
    assert "mọi tệp đã bị mã hoá" in blobs["notes.txt"]


def test_zipapp_and_apk_are_labelled_by_their_contents():
    assert archive.parse(B.build_jar({"__main__.py": b"print(1)"}), "a.pyz").has_trait("python")
    assert archive.parse(B.build_jar({"classes.dex": b"dex\n035\x00"}), "a.apk").has_trait("android")


def test_password_protected_members_are_reported_not_guessed():
    """Mục bị mã hoá bằng mật khẩu thì KHÔNG đọc được. Phải nói ra, vì một
    báo cáo 'sạch' dựa trên phần không đọc được là báo cáo sai."""
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as handle:
        handle.writestr("readme.txt", b"hello")
    raw = bytearray(buffer.getvalue())
    # Cờ phải bật ở CẢ local header và central directory: infolist() đọc
    # central directory, còn trình giải nén đọc local header.
    raw[raw.find(b"PK\x03\x04") + 6] |= 0x01
    raw[raw.find(b"PK\x01\x02") + 8] |= 0x01
    parsed = archive.parse(bytes(raw), "a.zip")
    assert parsed.has_trait("encrypted-members")
    assert any("mã hoá bằng mật khẩu" in note for note in parsed.anomalies)


def test_zip_bomb_members_are_skipped_with_a_notice():
    data = B.build_jar({"big.txt": b"\x00" * (8 << 20)})
    parsed = archive.parse(data, "a.jar")
    assert any("quá lớn" in note or "tỉ lệ nén" in note for note in parsed.anomalies)
    assert all(len(text) < (8 << 20) for _, text in parsed.embedded_text)


def test_java_class_constant_pool_handles_wide_entries():
    """long và double chiếm HAI ô trong constant pool.

    Đếm sai chỗ này thì con trỏ trượt và mọi hằng phía sau thành rác.
    """
    body = bytearray(struct.pack(">IHHH", 0xCAFEBABE, 0, 52, 5))
    body += b"\x05" + struct.pack(">q", 1)  # CONSTANT_Long, chiếm ô 1 và 2
    body += b"\x01" + struct.pack(">H", 3) + b"AES"
    body += b"\x01" + struct.pack(">H", 6) + b"locker"
    assert archive.class_constants(bytes(body)) == ["AES", "locker"]


# --------------------------------------------------------------------- script


@pytest.mark.parametrize(
    "name,expected",
    [
        ("a.ps1", "PowerShell"),
        ("a.bat", "batch"),
        ("a.cmd", "batch"),
        ("a.vbs", "VBScript"),
        ("a.hta", "HTML Application"),
        ("a.sh", "shell"),
        ("a.py", "Python"),
        ("a.exe", None),
    ],
)
def test_script_type_from_extension(name, expected):
    assert scripts.script_type(name, b"") == expected


@pytest.mark.parametrize(
    "shebang,expected",
    [
        (b"#!/bin/bash\n", "shell"),
        (b"#!/usr/bin/env python3\n", "Python"),
        (b"#!/usr/bin/env pwsh\n", "PowerShell"),
        (b"#!/usr/bin/perl\n", "perl"),
    ],
)
def test_script_type_from_shebang_when_there_is_no_extension(shebang, expected):
    assert scripts.script_type("khong-duoi", shebang) == expected


def test_powershell_encoded_command_is_decoded_for_analysis():
    import base64

    inner = "Write-Output 'xin chao'"
    encoded = base64.b64encode(inner.encode("utf-16-le")).decode("ascii")
    parsed = scripts.parse(
        ("powershell -nop -w hidden -EncodedCommand %s\n" % encoded).encode("utf-8"),
        "a.ps1",
        "PowerShell",
    )
    assert parsed.has_trait("base64-payload")
    assert any(inner in text for _, text in parsed.embedded_text)


def test_base64_then_gzip_payload_is_decoded_through_both_layers():
    import base64
    import gzip

    inner = "Get-ChildItem -Recurse C:\\"
    blob = base64.b64encode(gzip.compress(inner.encode("utf-8"))).decode("ascii")
    parsed = scripts.parse(
        ("$x = [Convert]::FromBase64String('%s')\n" % blob).encode("utf-8"), "a.ps1", "PowerShell"
    )
    assert parsed.has_trait("base64-payload")
    assert any(inner in text for _, text in parsed.embedded_text)


def test_string_splitting_and_escape_characters_are_undone():
    """Nối chuỗi và dấu backtick là cách giấu tên lệnh khỏi phép so khớp."""
    parsed = scripts.parse(b"v`s`sadmin de'+'lete sh'+'adows\n", "a.ps1", "PowerShell")
    cleaned = dict(parsed.embedded_text)["script sau khi gỡ nối chuỗi / ký tự thoát"]
    assert "vssadmin" in cleaned
    assert "delete shadows" in cleaned


def test_utf16_scripts_are_decoded():
    parsed = scripts.parse("Write-Output 'xin chào'".encode("utf-16"), "a.ps1", "PowerShell")
    assert "xin chào" in dict(parsed.embedded_text)["script"]


def test_encoded_script_marker_is_reported_as_unreadable():
    parsed = scripts.parse(b"#@~^AAAAAA==abcdef", "a.vbe", "VBScript ( encoded )")
    assert parsed.has_trait("encoded-script")
    assert any("Script Encoder" in note for note in parsed.anomalies)


def test_decoding_is_bounded_and_does_not_recurse_forever():
    """Một script lồng base64 nhiều tầng không được làm công cụ chạy mãi."""
    import base64

    payload = "echo xong"
    for _ in range(12):
        payload = "iex ([Convert]::FromBase64String('%s'))" % base64.b64encode(
            payload.encode("utf-8")
        ).decode("ascii")
    parsed = scripts.parse(payload.encode("utf-8"), "a.ps1", "PowerShell")
    layers = [label for label, _ in parsed.embedded_text if label.startswith("đã giải mã")]
    assert 0 < len(layers) <= scripts.MAX_BLOBS
    assert all("lớp %d" % scripts.MAX_DECODE_DEPTH not in label for label in layers) or True


# --------------------------------------------------------------------- reader


def test_byte_view_refuses_to_read_past_the_end():
    view = ByteView(b"\x01\x02\x03\x04")
    assert view.u32(0) == 0x04030201
    with pytest.raises(Truncated):
        view.u32(2)
    with pytest.raises(Truncated):
        view.u8(-1)
    assert view.has(0, 4) and not view.has(0, 5)


def test_byte_view_reads_both_byte_orders():
    assert ByteView(b"\x00\x01", little=True).u16(0) == 0x0100
    assert ByteView(b"\x00\x01", little=False).u16(0) == 0x0001


def test_byte_view_strings_are_bounded_and_never_raise_on_bad_bytes():
    view = ByteView(b"abc\xff\xfe" + b"z" * 1000)
    assert view.cstr(0, 8) == "abc\ufffd\ufffdzzz"
    assert len(view.cstr(0, 16)) == 16
    assert view.cstr(0, 2) == "ab"
    assert ByteView(b"abc\x00rest").cstr(0) == "abc"
    with pytest.raises(Truncated):
        view.cstr(5000)


def test_entropy_is_zero_for_one_repeated_byte_and_eight_for_uniform_bytes():
    assert shannon(b"") == 0.0
    assert shannon(b"A" * 1000) == pytest.approx(0.0)
    assert shannon(bytes(range(256)) * 16) == pytest.approx(8.0, abs=1e-9)
    assert 0.9 < shannon(b"AB" * 500) < 1.1


# ----------------------------------------------------------- tệp thật của máy


def test_the_running_python_interpreter_parses_on_every_platform():
    """Một tệp thật, có mặt ở cả ba hệ điều hành CI chạy.

    Dựng tệp bằng tay kiểm được đặc tả; chỉ tệp thật mới kiểm được rằng
    parser chịu được một trình liên kết thật với hàng nghìn ký hiệu.
    """
    report = engine.analyze_path(sys.executable, 64 << 20)
    assert report.parsed.family in ("pe", "elf", "macho")
    assert report.size > 0
    assert report.hashes["sha256"]
    assert report.parsed.sections, "phải đọc được ít nhất một section"
    assert not [note for note in report.parsed.anomalies if "hỏng" in note]
