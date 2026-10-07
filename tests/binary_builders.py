"""Dựng tệp thực thi bằng tay, từng byte, cho bộ kiểm tra.

Vì sao phải tự dựng thay vì lấy tệp có sẵn trên máy:

* Bộ kiểm tra chạy trên Linux, Windows và macOS. Tệp hệ thống khác nhau ở cả
  ba, nên bài kiểm tra dựa vào chúng sẽ xanh ở một nơi và đỏ ở nơi khác.
* Phải kiểm được những tệp HỎNG và THÙ ĐỊCH: header khai số mục giả, offset
  trỏ ra ngoài tệp, cây resource có vòng lặp. Không có tệp thật nào như vậy.
* Và quan trọng nhất: bộ dò ransomware phải được kiểm bằng tệp CÓ dấu hiệu.
  Ở đây dấu hiệu là những CHUỖI VĂN BẢN nằm trong section dữ liệu - không có
  một dòng mã thực thi nào. Đó là dữ liệu kiểm tra cho bộ dò, không phải mã
  độc: tệp dựng ra không chạy được và không làm gì cả.
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# ----------------------------------------------------------------------- PE

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
HEADER_SIZE = 0x400

SECTION_CODE = 0x00000020
SECTION_INITIALIZED = 0x00000040
SECTION_UNINITIALIZED = 0x00000080
SECTION_EXECUTE = 0x20000000
SECTION_READ = 0x40000000
SECTION_WRITE = 0x80000000

TEXT_FLAGS = SECTION_CODE | SECTION_EXECUTE | SECTION_READ
DATA_FLAGS = SECTION_INITIALIZED | SECTION_READ
RDATA_FLAGS = SECTION_INITIALIZED | SECTION_READ


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


class PeSection:
    def __init__(
        self,
        name: str,
        data: bytes = b"",
        flags: int = DATA_FLAGS,
        virtual_size: Optional[int] = None,
    ) -> None:
        self.name = name
        self.data = data
        self.flags = flags
        self.virtual_size = len(data) if virtual_size is None else virtual_size
        self.rva = 0
        self.offset = 0


def _place(sections: Sequence["PeSection"]) -> int:
    """Gán offset tệp và RVA cho từng section; trả về SizeOfImage.

    Section không có byte nào trên đĩa ( UPX0, .bss ) KHÔNG chiếm chỗ trong
    tệp: SizeOfRawData bằng 0 thì PointerToRawData cũng phải bằng 0, nếu
    không loader sẽ đọc dữ liệu của section sau.
    """
    offset = HEADER_SIZE
    rva = SECTION_ALIGNMENT
    for section in sections:
        section.rva = rva
        if section.data:
            section.offset = offset
            offset += _align(len(section.data), FILE_ALIGNMENT)
        else:
            section.offset = 0
        rva += _align(max(section.virtual_size, len(section.data), 1), SECTION_ALIGNMENT)
    return rva


def _import_blob(libraries: Dict[str, Sequence[str]], rva: int, pe32_plus: bool) -> bytes:
    """Bảng import hoàn chỉnh, tự tính RVA bên trong theo `rva` của section."""
    word = 8 if pe32_plus else 4
    descriptor_size = (len(libraries) + 1) * 20
    thunk_sizes = [(len(names) + 1) * word for names in libraries.values()]
    names_offset = descriptor_size + sum(thunk_sizes)

    hint_table = bytearray()
    hint_rva: Dict[Tuple[str, str], int] = {}
    library_rva: Dict[str, int] = {}
    for library, names in libraries.items():
        for name in names:
            hint_rva[(library, name)] = rva + names_offset + len(hint_table)
            hint_table += struct.pack("<H", 0) + name.encode("ascii") + b"\x00"
            if len(hint_table) % 2:
                hint_table += b"\x00"
    for library in libraries:
        library_rva[library] = rva + names_offset + len(hint_table)
        hint_table += library.encode("ascii") + b"\x00"

    descriptors = bytearray()
    thunks = bytearray()
    cursor = descriptor_size
    for index, (library, names) in enumerate(libraries.items()):
        thunk_rva = rva + cursor
        descriptors += struct.pack(
            "<IIIII", thunk_rva, 0, 0, library_rva[library], thunk_rva
        )
        for name in names:
            thunks += struct.pack("<Q" if pe32_plus else "<I", hint_rva[(library, name)])
        thunks += b"\x00" * word
        cursor += thunk_sizes[index]
    descriptors += b"\x00" * 20
    return bytes(descriptors + thunks + hint_table)


def _resource_blob(entries: Sequence[Tuple[int, str, bytes]], rva: int) -> bytes:
    """Cây resource ba tầng ( loại -> tên -> ngôn ngữ ) cho các mục đã cho."""
    by_type: Dict[int, List[Tuple[str, bytes]]] = {}
    for type_id, name, body in entries:
        by_type.setdefault(type_id, []).append((name, body))

    root_size = 16 + len(by_type) * 8
    name_dir_size = sum(16 + len(items) * 8 for items in by_type.values())
    lang_dir_count = sum(len(items) for items in by_type.values())
    lang_dir_size = lang_dir_count * (16 + 8)
    data_entry_size = lang_dir_count * 16
    strings_at = root_size + name_dir_size + lang_dir_size + data_entry_size

    strings = bytearray()
    string_offset: Dict[str, int] = {}
    for items in by_type.values():
        for name, _ in items:
            if name in string_offset:
                continue
            string_offset[name] = strings_at + len(strings)
            encoded = name.encode("utf-16-le")
            strings += struct.pack("<H", len(name)) + encoded
    payload_at = _align(strings_at + len(strings), 4)

    root = bytearray(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, len(by_type)))
    name_dirs = bytearray()
    lang_dirs = bytearray()
    data_entries = bytearray()
    payload = bytearray()

    name_dir_cursor = root_size
    lang_dir_cursor = root_size + name_dir_size
    data_entry_cursor = root_size + name_dir_size + lang_dir_size

    for type_id, items in by_type.items():
        root += struct.pack("<II", type_id, 0x80000000 | name_dir_cursor)
        name_dirs += struct.pack("<IIHHHH", 0, 0, 0, 0, len(items), 0)
        name_dir_cursor += 16 + len(items) * 8
        for name, body in items:
            name_dirs += struct.pack(
                "<II", 0x80000000 | string_offset[name], 0x80000000 | lang_dir_cursor
            )
            lang_dirs += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1)
            lang_dirs += struct.pack("<II", 0x409, data_entry_cursor)
            lang_dir_cursor += 24
            data_entries += struct.pack("<IIII", rva + payload_at + len(payload), len(body), 0, 0)
            data_entry_cursor += 16
            payload += body
            while len(payload) % 4:
                payload += b"\x00"

    blob = bytearray(root + name_dirs + lang_dirs + data_entries + strings)
    while len(blob) < payload_at:
        blob += b"\x00"
    return bytes(blob + payload)


def version_resource(fields: Dict[str, str]) -> bytes:
    """Resource VERSION đủ để parser rút được cặp khoá/giá trị StringFileInfo.

    Không dựng lại toàn bộ VS_VERSIONINFO: parser chỉ tìm cặp chuỗi UTF-16
    "khoá\\0giá trị\\0", nên đây là đúng hình dạng mà nó đọc.
    """
    body = bytearray("StringFileInfo\x00040904b0\x00".encode("utf-16-le"))
    for key, value in fields.items():
        body += ("%s\x00%s\x00" % (key, value)).encode("utf-16-le")
    return bytes(body)


def build_pe(
    sections: Optional[Sequence[PeSection]] = None,
    imports: Optional[Dict[str, Sequence[str]]] = None,
    resources: Optional[Sequence[Tuple[int, str, bytes]]] = None,
    exports: Optional[Sequence[str]] = None,
    overlay: bytes = b"",
    certificate: bytes = b"",
    timestamp: int = 0x5F000000,
    machine: int = 0x8664,
    dll: bool = False,
    driver: bool = False,
    aslr: bool = True,
    entry_rva: Optional[int] = None,
    clr: bool = False,
    clr_metadata: bytes = b"",
    section_count_override: Optional[int] = None,
    e_lfanew_override: Optional[int] = None,
    directory_override: Optional[Dict[int, Tuple[int, int]]] = None,
) -> bytes:
    """Một PE32+ ( hoặc PE32 ) hợp lệ về cấu trúc, dựng từ các mảnh đã cho."""
    pe32_plus = machine in (0x8664, 0xAA64, 0x200)
    body = [PeSection(".text", b"\xc3" * 16, TEXT_FLAGS)] if sections is None else list(sections)

    generated: List[PeSection] = []
    if imports:
        generated.append(PeSection(".idata", b"", RDATA_FLAGS))
    if resources:
        generated.append(PeSection(".rsrc", b"", RDATA_FLAGS))
    if exports:
        generated.append(PeSection(".edata", b"", RDATA_FLAGS))
    if clr:
        generated.append(PeSection(".cormeta", b"", RDATA_FLAGS))
    ordered = body + generated

    _place(ordered)

    directories: Dict[int, Tuple[int, int]] = {}
    if imports:
        target = next(s for s in ordered if s.name == ".idata")
        target.data = _import_blob(dict(imports), target.rva, pe32_plus)
        target.virtual_size = len(target.data)
        directories[1] = (target.rva, len(target.data))
    if resources:
        target = next(s for s in ordered if s.name == ".rsrc")
        target.data = _resource_blob(resources, target.rva)
        target.virtual_size = len(target.data)
        directories[2] = (target.rva, len(target.data))
    if exports:
        target = next(s for s in ordered if s.name == ".edata")
        target.data, export_size = _export_blob(exports, target.rva)
        target.virtual_size = len(target.data)
        directories[0] = (target.rva, export_size)
    if clr:
        target = next(s for s in ordered if s.name == ".cormeta")
        metadata = clr_metadata or dotnet_metadata()
        # IMAGE_COR20_HEADER dài đúng 72 byte; metadata nằm ngay sau nó.
        header = struct.pack(
            "<IHHIIII", 72, 2, 5, target.rva + 72, len(metadata), 0x1, 0
        )
        header += b"\x00" * (72 - len(header))
        target.data = header + metadata
        target.virtual_size = len(target.data)
        directories[14] = (target.rva, 72)

    # Sắp lại offset tệp sau khi nội dung thật đã có.
    image_size = _place(ordered)

    if directory_override:
        directories.update(directory_override)

    entry = entry_rva
    if entry is None:
        executable = next((s for s in ordered if s.flags & SECTION_EXECUTE), ordered[0])
        entry = executable.rva

    e_lfanew = 0x80
    optional_size = 240 if pe32_plus else 224
    characteristics = 0x0022 | (0x2000 if dll else 0)
    file_header = struct.pack(
        "<HHIIIHH",
        machine,
        len(ordered) if section_count_override is None else section_count_override,
        timestamp,
        0,
        0,
        optional_size,
        characteristics,
    )
    subsystem = 1 if driver else 3
    dll_characteristics = (0x40 if aslr else 0) | 0x100 | 0x8000
    if pe32_plus:
        optional = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x20B, 14, 0, sum(len(s.data) for s in ordered if s.flags & SECTION_CODE), 0, 0,
            entry, SECTION_ALIGNMENT, 0x140000000, SECTION_ALIGNMENT, FILE_ALIGNMENT,
            6, 0, 0, 0, 6, 0, 0, image_size, HEADER_SIZE, 0, subsystem, dll_characteristics,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )
    else:
        optional = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B, 14, 0, sum(len(s.data) for s in ordered if s.flags & SECTION_CODE), 0, 0,
            entry, SECTION_ALIGNMENT, 0, 0x400000, SECTION_ALIGNMENT, FILE_ALIGNMENT,
            6, 0, 0, 0, 6, 0, 0, image_size, HEADER_SIZE, 0, subsystem, dll_characteristics,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )
    table = bytearray()
    for index in range(16):
        table += struct.pack("<II", *directories.get(index, (0, 0)))

    section_table = bytearray()
    for section in ordered:
        section_table += struct.pack(
            "<8sIIIIIIHHI",
            section.name.encode("latin-1")[:8],
            max(section.virtual_size, len(section.data)),
            section.rva,
            _align(len(section.data), FILE_ALIGNMENT),
            section.offset if section.data else 0,
            0, 0, 0, 0,
            section.flags,
        )

    image = bytearray(b"MZ" + b"\x90" * 0x3A)
    image += struct.pack("<I", e_lfanew)
    while len(image) < e_lfanew:
        image += b"\x00"
    image += b"PE\x00\x00" + file_header + optional + bytes(table) + bytes(section_table)
    assert len(image) <= HEADER_SIZE, "header vượt quá chỗ dành cho nó"
    image += b"\x00" * (HEADER_SIZE - len(image))
    for section in ordered:
        if not section.data:
            continue
        assert len(image) == section.offset
        image += section.data
        image += b"\x00" * (_align(len(section.data), FILE_ALIGNMENT) - len(section.data))
    image += overlay
    if e_lfanew_override is not None:
        # Sửa SAU khi dựng: một e_lfanew trỏ ra ngoài tệp là đột biến thù địch,
        # không phải một tệp hợp lệ có header nằm xa.
        image[0x3C:0x40] = struct.pack("<I", e_lfanew_override)
    if certificate:
        certificate_offset = len(image)
        entry_blob = struct.pack("<IHH", len(certificate) + 8, 0x200, 2) + certificate
        image += entry_blob
        position = e_lfanew + 4 + 20 + (112 if pe32_plus else 96) + 4 * 8
        image[position : position + 8] = struct.pack("<II", certificate_offset, len(entry_blob))
    return bytes(image)


def _export_blob(names: Sequence[str], rva: int) -> Tuple[bytes, int]:
    count = len(names)
    directory_size = 40
    functions_at = directory_size
    names_at = functions_at + count * 4
    ordinals_at = names_at + count * 4
    strings_at = ordinals_at + count * 2

    strings = bytearray(b"sample.dll\x00")
    name_rvas = []
    for name in names:
        name_rvas.append(rva + strings_at + len(strings))
        strings += name.encode("ascii") + b"\x00"

    directory = struct.pack(
        "<IIHHIIIIIII",
        0, 0, 0, 0,
        rva + strings_at,
        1,
        count,
        count,
        rva + functions_at,
        rva + names_at,
        rva + ordinals_at,
    )
    functions = b"".join(struct.pack("<I", rva + 0x1000 + index) for index in range(count))
    name_table = b"".join(struct.pack("<I", value) for value in name_rvas)
    ordinals = b"".join(struct.pack("<H", index) for index in range(count))
    blob = directory + functions + name_table + ordinals + bytes(strings)
    return blob, len(blob)


def dotnet_metadata(
    identifiers: Iterable[str] = ("Program", "Main", "System"),
    user_strings: Iterable[str] = (),
    runtime: str = "v4.0.30319",
) -> bytes:
    """Khối metadata .NET với heap #Strings và #US thật."""
    strings_heap = bytearray(b"\x00")
    for name in identifiers:
        strings_heap += name.encode("utf-8") + b"\x00"
    while len(strings_heap) % 4:
        strings_heap += b"\x00"

    user_heap = bytearray(b"\x00")
    for value in user_strings:
        encoded = value.encode("utf-16-le") + b"\x00"
        size = len(encoded)
        if size < 0x80:
            user_heap += bytes([size])
        else:
            user_heap += bytes([0x80 | (size >> 8), size & 0xFF])
        user_heap += encoded
    while len(user_heap) % 4:
        user_heap += b"\x00"

    version = runtime.encode("ascii") + b"\x00"
    while len(version) % 4:
        version += b"\x00"
    # BSJB, major, minor, reserved, độ dài chuỗi phiên bản ( ECMA-335 II.24.2.1 ).
    header = bytearray(struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version)
    streams = [(b"#Strings\x00\x00\x00\x00", bytes(strings_heap))]
    if user_strings:
        streams.append((b"#US\x00", bytes(user_heap)))
    header += struct.pack("<HH", 0, len(streams))

    directory_size = sum(8 + len(name) for name, _ in streams)
    cursor = len(header) + directory_size
    directory = bytearray()
    for name, blob in streams:
        directory += struct.pack("<II", cursor, len(blob)) + name
        cursor += len(blob)
    return bytes(header + directory + b"".join(blob for _, blob in streams))


def pyinstaller_overlay(scripts: Dict[str, bytes], extra: Sequence[str] = ()) -> bytes:
    """Gói PyInstaller ( CArchive ) với mục lục và script nén zlib."""
    entries: List[Tuple[bytes, int, int, int, str, bytes]] = []
    payload = bytearray()
    for name, content in scripts.items():
        compressed = zlib.compress(content)
        entries.append((name.encode("ascii"), len(payload), len(compressed), 1, "s", compressed))
        payload += compressed
    for name in extra:
        blob = b"\x00" * 32
        entries.append((name.encode("ascii"), len(payload), len(blob), 0, "b", blob))
        payload += blob

    table = bytearray()
    for name, position, size, flag, kind, _ in entries:
        entry_size = 18 + len(name) + 1
        table += struct.pack(
            ">IIIIBc", entry_size, position, size, size, flag, kind.encode("ascii")
        )
        table += name + b"\x00"

    toc_offset = len(payload)
    package = bytes(payload + table)
    cookie = b"MEI\x0c\x0b\x0a\x0b\x0e" + struct.pack(
        ">IIII", len(package) + 24, toc_offset, len(table), 311
    )
    return package + cookie


# ---------------------------------------------------------------------- ELF

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8
SHT_DYNAMIC = 6
SHT_DYNSYM = 11
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXEC = 0x4


class ElfSection:
    def __init__(
        self,
        name: str,
        data: bytes = b"",
        sh_type: int = SHT_PROGBITS,
        flags: int = SHF_ALLOC,
        link: int = 0,
        entry_size: int = 0,
    ) -> None:
        self.name = name
        self.data = data
        self.sh_type = sh_type
        self.flags = flags
        self.link = link
        self.entry_size = entry_size
        self.offset = 0


def build_elf(
    sections: Optional[Sequence[ElfSection]] = None,
    imported: Sequence[str] = (),
    exported: Sequence[str] = (),
    local_symbols: Sequence[str] = (),
    needed: Sequence[str] = (),
    interpreter: Optional[str] = "/lib64/ld-linux-x86-64.so.2",
    machine: int = 0x3E,
    elf_type: int = 2,
    bits64: bool = True,
    little: bool = True,
    entry: int = 0x1000,
    executable_stack: bool = False,
    writable_executable: bool = False,
    drop_section_headers: bool = False,
    section_count_override: Optional[int] = None,
) -> bytes:
    """ELF hợp lệ về cấu trúc, ánh xạ địa chỉ ảo trùng offset tệp cho đơn giản."""
    prefix = "<" if little else ">"
    word = "Q" if bits64 else "I"
    body = list(sections) if sections is not None else [
        ElfSection(".text", b"\x90" * 32, SHT_PROGBITS, SHF_ALLOC | SHF_EXEC)
    ]

    dynstr = bytearray(b"\x00")
    symbol_rows: List[Tuple[int, int, int]] = []  # (st_name, info, shndx)
    for name in imported:
        symbol_rows.append((len(dynstr), (1 << 4) | 2, 0))
        dynstr += name.encode("ascii") + b"\x00"
    for name in exported:
        symbol_rows.append((len(dynstr), (1 << 4) | 2, 1))
        dynstr += name.encode("ascii") + b"\x00"
    needed_offsets = []
    for library in needed:
        needed_offsets.append(len(dynstr))
        dynstr += library.encode("ascii") + b"\x00"

    strtab = bytearray(b"\x00")
    local_rows: List[Tuple[int, int, int]] = []
    for name in local_symbols:
        local_rows.append((len(strtab), 2, 1))
        strtab += name.encode("ascii") + b"\x00"

    layout = list(body)
    index_of: Dict[str, int] = {}

    def add(section: ElfSection) -> int:
        layout.append(section)
        index_of[section.name] = len(layout)  # +1 vì có section rỗng ở đầu
        return len(layout)

    if symbol_rows or needed_offsets:
        dynstr_index = add(ElfSection(".dynstr", bytes(dynstr), SHT_STRTAB, SHF_ALLOC))
    if symbol_rows:
        symbol_size = 24 if bits64 else 16
        blob = bytearray(b"\x00" * symbol_size)
        for st_name, info, shndx in symbol_rows:
            if bits64:
                blob += struct.pack(prefix + "IBBHQQ", st_name, info, 0, shndx, 0x2000, 0)
            else:
                blob += struct.pack(prefix + "IIIBBH", st_name, 0x2000, 0, info, 0, shndx)
        add(
            ElfSection(
                ".dynsym", bytes(blob), SHT_DYNSYM, SHF_ALLOC, dynstr_index, symbol_size
            )
        )
    if local_rows:
        symbol_size = 24 if bits64 else 16
        strtab_index = add(ElfSection(".strtab", bytes(strtab), SHT_STRTAB, 0))
        blob = bytearray(b"\x00" * symbol_size)
        for st_name, info, shndx in local_rows:
            if bits64:
                blob += struct.pack(prefix + "IBBHQQ", st_name, info, 0, shndx, 0x3000, 0)
            else:
                blob += struct.pack(prefix + "IIIBBH", st_name, 0x3000, 0, info, 0, shndx)
        add(
            ElfSection(
                ".symtab", bytes(blob), SHT_SYMTAB, 0, strtab_index, symbol_size
            )
        )

    names = bytearray(b"\x00")
    name_offset: Dict[str, int] = {}
    for section in layout:
        name_offset[section.name] = len(names)
        names += section.name.encode("ascii") + b"\x00"
    name_offset[".shstrtab"] = len(names)
    names += b".shstrtab\x00"
    shstrtab = ElfSection(".shstrtab", bytes(names), SHT_STRTAB, 0)
    layout.append(shstrtab)
    shstrndx = len(layout)

    header_size = 64 if bits64 else 52
    phentsize = 56 if bits64 else 32
    program_headers = 1 + (1 if interpreter else 0) + 1
    dynamic_present = bool(needed_offsets)
    if dynamic_present:
        program_headers += 1
    cursor = _align(header_size + program_headers * phentsize, 16)

    interp_offset = 0
    if interpreter:
        interp_offset = cursor
        cursor += len(interpreter) + 1
        cursor = _align(cursor, 16)
    for section in layout:
        section.offset = cursor
        if section.sh_type != SHT_NOBITS:
            cursor += len(section.data)
        cursor = _align(cursor, 16)

    dynamic_offset = 0
    dynamic_blob = b""
    if dynamic_present:
        dynstr_section = next(s for s in layout if s.name == ".dynstr")
        rows = [(5, dynstr_section.offset), (10, len(dynstr_section.data))]
        rows += [(1, value) for value in needed_offsets]
        rows.append((0, 0))
        dynamic_blob = b"".join(struct.pack(prefix + word * 2, tag, value) for tag, value in rows)
        dynamic_offset = cursor
        cursor += len(dynamic_blob)
        cursor = _align(cursor, 16)

    shoff = 0 if drop_section_headers else cursor
    shentsize = 64 if bits64 else 40
    total = cursor + (0 if drop_section_headers else (len(layout) + 1) * shentsize)

    if bits64:
        ident = b"\x7fELF\x02" + (b"\x01" if little else b"\x02") + b"\x01" + b"\x00" * 9
        header = ident + struct.pack(
            prefix + "HHIQQQIHHHHHH",
            elf_type, machine, 1, entry, header_size, shoff, 0,
            header_size, phentsize, program_headers, shentsize,
            0 if drop_section_headers else len(layout) + 1,
            0 if drop_section_headers else shstrndx,
        )
    else:
        ident = b"\x7fELF\x01" + (b"\x01" if little else b"\x02") + b"\x01" + b"\x00" * 9
        header = ident + struct.pack(
            prefix + "HHIIIIIHHHHHH",
            elf_type, machine, 1, entry, header_size, shoff, 0,
            header_size, phentsize, program_headers, shentsize,
            0 if drop_section_headers else len(layout) + 1,
            0 if drop_section_headers else shstrndx,
        )

    load_flags = 0x4 | 0x1 | (0x2 if writable_executable else 0)
    phdrs = bytearray()

    def phdr(p_type: int, offset: int, size: int, flags: int) -> bytes:
        if bits64:
            return struct.pack(
                prefix + "IIQQQQQQ", p_type, flags, offset, offset, offset, size, size, 0x1000
            )
        return struct.pack(
            prefix + "IIIIIIII", p_type, offset, offset, offset, size, size, flags, 0x1000
        )

    phdrs += phdr(PT_LOAD, 0, total, load_flags)
    if interpreter:
        phdrs += phdr(PT_INTERP, interp_offset, len(interpreter) + 1, 0x4)
    if dynamic_present:
        phdrs += phdr(PT_DYNAMIC, dynamic_offset, len(dynamic_blob), 0x6)
    phdrs += phdr(PT_GNU_STACK, 0, 0, 0x6 | (0x1 if executable_stack else 0))

    image = bytearray(header)
    image += phdrs
    while len(image) < (interp_offset or layout[0].offset):
        image += b"\x00"
    if interpreter:
        image += interpreter.encode("ascii") + b"\x00"
    for section in layout:
        while len(image) < section.offset:
            image += b"\x00"
        if section.sh_type != SHT_NOBITS:
            image += section.data
    if dynamic_present:
        while len(image) < dynamic_offset:
            image += b"\x00"
        image += dynamic_blob
    if not drop_section_headers:
        while len(image) < shoff:
            image += b"\x00"
        empty = struct.pack(
            prefix + ("IIQQQQIIQQ" if bits64 else "IIIIIIIIII"), *([0] * 10)
        )
        image += empty
        for section in layout:
            if bits64:
                image += struct.pack(
                    prefix + "IIQQQQIIQQ",
                    name_offset[section.name], section.sh_type, section.flags,
                    section.offset, section.offset, len(section.data),
                    section.link, 0, 16, section.entry_size,
                )
            else:
                image += struct.pack(
                    prefix + "IIIIIIIIII",
                    name_offset[section.name], section.sh_type, section.flags,
                    section.offset, section.offset, len(section.data),
                    section.link, 0, 16, section.entry_size,
                )
    data = bytearray(image)
    if section_count_override is not None and not drop_section_headers:
        # e_shnum nằm ở offset tuyệt đối 60 ( ELF64 ) / 48 ( ELF32 ).
        position = 60 if bits64 else 48
        data[position : position + 2] = struct.pack(prefix + "H", section_count_override)
    return bytes(data)


# ------------------------------------------------------------------- Mach-O

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_CODE_SIGNATURE = 0x1D
LC_MAIN = 0x80000028


def build_macho(
    segments: Sequence[Tuple[str, Sequence[Tuple[str, bytes]], int]] = (),
    imported: Sequence[str] = (),
    exported: Sequence[str] = (),
    dylibs: Sequence[str] = ("/usr/lib/libSystem.B.dylib",),
    cpu: int = 0x01000007,
    filetype: int = 2,
    pie: bool = True,
    code_signature: bytes = b"",
    command_count_override: Optional[int] = None,
) -> bytes:
    """Mach-O 64-bit thin, các load command dựng theo đúng đặc tả."""
    if not segments:
        segments = (("__TEXT", (("__text", b"\xc3" * 16),), 0x5),)

    commands = bytearray()
    payload = bytearray()
    string_table = bytearray(b"\x00")
    symbols: List[Tuple[int, int]] = []
    for name in imported:
        symbols.append((len(string_table), 0x01))
        string_table += ("_" + name).encode("ascii") + b"\x00"
    for name in exported:
        symbols.append((len(string_table), 0x0F))
        string_table += ("_" + name).encode("ascii") + b"\x00"

    header_size = 32
    segment_command_size = {}
    for segname, sects, _ in segments:
        segment_command_size[segname] = 72 + len(sects) * 80
    commands_size = sum(segment_command_size.values())
    commands_size += sum(_align(24 + len(name) + 1, 8) for name in dylibs)
    commands_size += 24 if symbols else 0
    commands_size += 24  # LC_MAIN
    commands_size += 16 if code_signature else 0

    cursor = _align(header_size + commands_size, 16)
    section_offsets: Dict[Tuple[str, str], Tuple[int, bytes]] = {}
    for segname, sects, _ in segments:
        for sectname, body in sects:
            section_offsets[(segname, sectname)] = (cursor + len(payload), body)
            payload += body
    symbol_offset = cursor + len(payload)
    symbol_blob = bytearray()
    for st_name, n_type in symbols:
        symbol_blob += struct.pack("<IBBHQ", st_name, n_type, 1, 0, 0x2000)
    payload += symbol_blob
    string_offset = cursor + len(payload)
    payload += string_table
    signature_offset = cursor + len(payload)
    payload += code_signature

    command_total = 0
    for segname, sects, protection in segments:
        first = section_offsets[(segname, sects[0][0])][0] if sects else cursor
        size = sum(len(body) for _, body in sects)
        commands += struct.pack(
            "<II16sQQQQIIII",
            LC_SEGMENT_64,
            segment_command_size[segname],
            segname.encode("ascii")[:16],
            first,
            size,
            first,
            size,
            0x7,
            protection,
            len(sects),
            0,
        )
        command_total += 1
        for sectname, body in sects:
            offset, _ = section_offsets[(segname, sectname)]
            commands += struct.pack(
                "<16s16sQQIIIIIIII",
                sectname.encode("ascii")[:16],
                segname.encode("ascii")[:16],
                offset,
                len(body),
                offset,
                4,
                0,
                0,
                0,
                0,
                0,
                0,
            )
    for name in dylibs:
        encoded = name.encode("ascii") + b"\x00"
        size = _align(24 + len(encoded), 8)
        commands += struct.pack("<IIIIII", LC_LOAD_DYLIB, size, 24, 0, 0, 0) + encoded
        commands += b"\x00" * (size - 24 - len(encoded))
        command_total += 1
    if symbols:
        commands += struct.pack(
            "<IIIIII", LC_SYMTAB, 24, symbol_offset, len(symbols), string_offset, len(string_table)
        )
        command_total += 1
    commands += struct.pack("<IIQQ", LC_MAIN, 24, 0x1000, 0)
    command_total += 1
    if code_signature:
        commands += struct.pack("<IIII", LC_CODE_SIGNATURE, 16, signature_offset, len(code_signature))
        command_total += 1

    flags = 0x200000 if pie else 0
    header = struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64,
        cpu,
        3,
        filetype,
        command_total if command_count_override is None else command_count_override,
        len(commands),
        flags,
        0,
    )
    image = bytearray(header + bytes(commands))
    while len(image) < cursor:
        image += b"\x00"
    image += payload
    return bytes(image)


def build_fat_macho(slices: Sequence[bytes], cpus: Sequence[int] = ()) -> bytes:
    """Universal binary gói các lát Mach-O đã dựng."""
    if not cpus:
        cpus = [0x01000007, 0x0100000C][: len(slices)]
    header_size = _align(8 + len(slices) * 20, 0x1000)
    header = bytearray(b"\xca\xfe\xba\xbe" + struct.pack(">I", len(slices)))
    body = bytearray()
    for index, blob in enumerate(slices):
        offset = header_size + len(body)
        header += struct.pack(">IIIII", cpus[index], 3, offset, len(blob), 12)
        body += blob
        while len(body) % 0x1000:
            body += b"\x00"
    image = bytearray(header)
    while len(image) < header_size:
        image += b"\x00"
    return bytes(image + body)


# --------------------------------------------------------------- Java / ZIP


def build_class(constants: Sequence[str], major: int = 52) -> bytes:
    """Tệp .class với constant pool chỉ gồm các hằng Utf8."""
    pool = bytearray()
    for value in constants:
        encoded = value.encode("utf-8")
        pool += b"\x01" + struct.pack(">H", len(encoded)) + encoded
    header = struct.pack(">IHHH", 0xCAFEBABE, 0, major, len(constants) + 1)
    return header + bytes(pool) + struct.pack(">HHHHHHHH", 0x21, 1, 0, 0, 0, 0, 0, 0)


def build_jar(members: Dict[str, bytes], signed: bool = False) -> bytes:
    """JAR trong bộ nhớ; `members` là cặp đường-dẫn-trong-kho -> nội dung."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in members.items():
            archive.writestr(name, body)
        if signed:
            archive.writestr("META-INF/SAMPLE.RSA", b"\x30\x82\x00\x00")
    return buffer.getvalue()


# -------------------------------------------------- địa chỉ hợp checksum

import base64  # noqa: E402  ( gom các import "nặng" ở cuối cho dễ đọc phần dựng )
import hashlib  # noqa: E402

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def fake_onion_v3(seed: bytes = b"fortress-scan-test") -> str:
    """Địa chỉ .onion v3 có checksum ĐÚNG, sinh từ một khoá giả.

    Phải tự sinh thay vì gõ một địa chỉ có thật: bộ dò chỉ nhận địa chỉ qua
    được checksum, nên bài kiểm tra cần một địa chỉ hợp lệ, mà một địa chỉ
    hợp lệ có thật lại là hạ tầng của người khác và không nên nằm trong repo.
    """
    key = hashlib.sha256(seed).digest()
    checksum = hashlib.sha3_256(b".onion checksum" + key + b"\x03").digest()[:2]
    label = base64.b32encode(key + checksum + b"\x03").decode("ascii").lower()
    return label + ".onion"


def fake_bitcoin_address(seed: bytes = b"fortress-scan-test") -> str:
    """Địa chỉ Bitcoin P2PKH có checksum base58check ĐÚNG, sinh từ hash giả."""
    payload = b"\x00" + hashlib.sha256(seed).digest()[:20]
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    value = int.from_bytes(payload + checksum, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = _B58_ALPHABET[remainder] + encoded
    return "1" + encoded


def _bech32_polymod(values: Sequence[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for index in range(5):
            checksum ^= generator[index] if (top >> index) & 1 else 0
    return checksum


def fake_bech32_address(seed: bytes = b"fortress-scan-test") -> str:
    """Địa chỉ Bitcoin bech32 ( P2WPKH ) có checksum ĐÚNG."""
    program = hashlib.sha256(seed).digest()[:20]
    bits: List[int] = []
    accumulator = 0
    length = 0
    for byte in program:
        accumulator = (accumulator << 8) | byte
        length += 8
        while length >= 5:
            length -= 5
            bits.append((accumulator >> length) & 31)
    if length:
        bits.append((accumulator << (5 - length)) & 31)
    data = [0] + bits
    expanded = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    polymod = _bech32_polymod(expanded + data + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - index)) & 31 for index in range(6)]
    return "bc1" + "".join(_BECH32_ALPHABET[value] for value in data + checksum)
