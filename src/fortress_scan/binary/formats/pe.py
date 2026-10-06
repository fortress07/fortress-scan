"""Parser PE ( Windows .exe / .dll / .sys ) thuần Python, chỉ đọc.

Theo đặc tả "PE Format" của Microsoft. Mọi số đếm đọc từ tệp đều bị chặn
trần trước khi lặp, vì một header giả có thể khai hàng tỉ mục.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Optional, Set, Tuple

from ..entropy import shannon
from ..model import Import, Overlay, Parsed, Resource, Section, Signature
from ..reader import ByteView, Truncated
from . import dotnet

MAX_SECTIONS = 96  # trần của chính đặc tả
MAX_IMPORT_DLLS = 512
MAX_IMPORTS = 20_000
MAX_EXPORTS = 20_000
MAX_RESOURCES = 4096
MAX_RESOURCE_DEPTH = 6

_MACHINES = {
    0x14C: "x86",
    0x8664: "x86-64",
    0x1C0: "ARM",
    0x1C4: "ARMv7 Thumb-2",
    0xAA64: "ARM64",
    0x200: "IA-64",
    0x0: "không rõ",
}

_RESOURCE_TYPES = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    17: "DLGINCLUDE",
    19: "PLUGPLAY",
    20: "VXD",
    21: "ANICURSOR",
    22: "ANIICON",
    23: "HTML",
    24: "MANIFEST",
}

# Tên section của các packer / protector phổ biến ( theo tài liệu công khai của
# chính các công cụ và các bài phân tích của vendor ).
PACKER_SECTIONS = {
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    ".upx": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".petite": "Petite",
    ".nsp0": "NsPack",
    ".nsp1": "NsPack",
    ".mpress1": "MPRESS",
    ".mpress2": "MPRESS",
    ".themida": "Themida",
    ".winlice": "WinLicense",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".vmp2": "VMProtect",
    ".enigma1": "Enigma Protector",
    ".enigma2": "Enigma Protector",
    "pec1": "PECompact",
    "pec2": "PECompact",
    "pecompact2": "PECompact",
    ".packed": "packer không rõ tên",
    ".rlpack": "RLPack",
    ".yp": "Y0da Protector",
    ".perplex": "Perplex",
    "mew": "MEW",
    ".kkrunchy": "kkrunchy",
    ".boom": "Boomerang",
    ".taz": "PESpin",
    ".spack": "Simple Pack",
}

# Chữ ký đầu overlay của các trình cài đặt và tự giải nén. Biết được cái nào
# là để GIẢI THÍCH entropy cao một cách trung thực, không phải để tha bổng.
_OVERLAY_SIGNATURES: Tuple[Tuple[bytes, str], ...] = (
    (b"\xef\xbe\xad\xdeNullsoftInst", "trình cài đặt NSIS"),
    (b"Inno Setup Setup Data", "trình cài đặt Inno Setup"),
    (b"zlb\x1a", "trình cài đặt Inno Setup"),
    (b"7z\xbc\xaf\x27\x1c", "kho 7-Zip tự giải nén"),
    (b"PK\x03\x04", "kho ZIP"),
    (b"Rar!\x1a\x07", "kho RAR tự giải nén"),
    (b"MSCF", "kho CAB"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "gói MSI / OLE"),
)

_SECTION_FLAGS_CODE = 0x00000020
_SECTION_FLAGS_EXEC = 0x20000000
_SECTION_FLAGS_READ = 0x40000000
_SECTION_FLAGS_WRITE = 0x80000000

_VERSION_KEYS = (
    "CompanyName",
    "FileDescription",
    "FileVersion",
    "InternalName",
    "LegalCopyright",
    "OriginalFilename",
    "ProductName",
    "ProductVersion",
)


def looks_like(data: bytes) -> bool:
    return data[:2] == b"MZ"


class _PE:
    def __init__(self, data: bytes, parsed: Parsed) -> None:
        self.data = data
        self.view = ByteView(data)
        self.parsed = parsed
        self.is64 = False
        self.image_base = 0
        self.file_alignment = 0x200
        self.sections: List[Tuple[int, int, int, int, str]] = []  # va, vsize, raw_ptr, raw_size, name
        self.directories: List[Tuple[int, int]] = []

    def anomaly(self, message: str) -> None:
        if message not in self.parsed.anomalies and len(self.parsed.anomalies) < 64:
            self.parsed.anomalies.append(message)

    # --- ánh xạ địa chỉ -------------------------------------------------
    def raw_pointer(self, pointer: int) -> int:
        if self.file_alignment >= 0x200:
            return pointer & ~0x1FF
        return pointer

    def rva_to_offset(self, rva: int) -> Optional[int]:
        for va, vsize, raw_ptr, raw_size, _ in self.sections:
            span = max(vsize, raw_size)
            if va <= rva < va + span:
                delta = rva - va
                if delta >= raw_size:
                    return None  # phần chỉ có trong bộ nhớ ( .bss ), không có trên đĩa
                offset = self.raw_pointer(raw_ptr) + delta
                return offset if offset < len(self.data) else None
        if self.sections and rva < self.sections[0][0] and rva < len(self.data):
            return rva  # nằm trong vùng header
        if not self.sections and rva < len(self.data):
            return rva
        return None

    def section_of_rva(self, rva: int) -> Optional[str]:
        for va, vsize, _, raw_size, name in self.sections:
            if va <= rva < va + max(vsize, raw_size):
                return name
        return None

    def directory(self, index: int) -> Tuple[int, int]:
        if index < len(self.directories):
            return self.directories[index]
        return 0, 0

    # --- header ----------------------------------------------------------
    def parse(self) -> None:
        view = self.view
        parsed = self.parsed
        try:
            e_lfanew = view.u32(0x3C)
        except Truncated:
            self.anomaly("tệp bắt đầu bằng MZ nhưng quá ngắn để có header PE")
            parsed.format = "MS-DOS / MZ"
            return
        if not view.has(e_lfanew, 24) or view.bytes_at(e_lfanew, 4) != b"PE\x00\x00":
            parsed.format = "MS-DOS / MZ ( không có header PE hợp lệ )"
            self.anomaly("e_lfanew không trỏ tới chữ ký PE")
            return
        file_header = e_lfanew + 4
        machine = view.u16(file_header)
        section_count = view.u16(file_header + 2)
        parsed.timestamp = view.u32(file_header + 4)
        optional_size = view.u16(file_header + 16)
        characteristics = view.u16(file_header + 18)
        parsed.arch = _MACHINES.get(machine, "machine 0x%x" % machine)
        if characteristics & 0x2000:
            parsed.traits.append("dll")
        optional = file_header + 20
        try:
            magic = view.u16(optional)
        except Truncated:
            self.anomaly("thiếu optional header")
            return
        if magic == 0x20B:
            self.is64 = True
            parsed.format = "PE32+"
        elif magic == 0x10B:
            parsed.format = "PE32"
        else:
            parsed.format = "PE ( optional header lạ 0x%x )" % magic
            self.anomaly("magic của optional header không hợp lệ")
            return
        try:
            entry_rva = view.u32(optional + 16)
            if self.is64:
                self.image_base = view.u64(optional + 24)
            else:
                self.image_base = view.u32(optional + 28)
            self.file_alignment = view.u32(optional + 36)
            subsystem = view.u16(optional + 68)
            dll_characteristics = view.u16(optional + 70)
            count_at = optional + (108 if self.is64 else 92)
            directory_count = min(view.u32(count_at), 16)
            for index in range(directory_count):
                at = count_at + 4 + index * 8
                if not view.has(at, 8):
                    break
                self.directories.append((view.u32(at), view.u32(at + 4)))
        except Truncated:
            self.anomaly("optional header bị cắt cụt")
            return
        parsed.metadata["subsystem"] = {
            1: "native",
            2: "Windows GUI",
            3: "Windows console",
            9: "Windows CE",
            10: "EFI application",
            11: "EFI boot driver",
            12: "EFI runtime driver",
        }.get(subsystem, "subsystem %d" % subsystem)
        if not dll_characteristics & 0x40:
            parsed.traits.append("no-aslr")
        if subsystem == 1:
            parsed.traits.append("driver")

        if section_count > MAX_SECTIONS:
            self.anomaly("header khai %d section, vượt trần 96 của đặc tả" % section_count)
            section_count = MAX_SECTIONS
        table = optional + optional_size
        for index in range(section_count):
            at = table + index * 40
            if not view.has(at, 40):
                self.anomaly("bảng section bị cắt cụt")
                break
            raw_name = view.bytes_at(at, 8).split(b"\x00", 1)[0]
            name = raw_name.decode("latin-1")
            vsize = view.u32(at + 8)
            va = view.u32(at + 12)
            raw_size = view.u32(at + 16)
            raw_ptr = view.u32(at + 20)
            flags = view.u32(at + 36)
            self.sections.append((va, vsize, raw_ptr, raw_size, name))
            start = self.raw_pointer(raw_ptr)
            body = self.data[start : start + raw_size] if raw_size else b""
            if raw_size and start + raw_size > len(self.data):
                self.anomaly("section %r khai dữ liệu vượt cuối tệp" % name)
            parsed.sections.append(
                Section(
                    name=name,
                    offset=start,
                    raw_size=raw_size,
                    virtual_size=vsize,
                    entropy=shannon(body),
                    readable=bool(flags & _SECTION_FLAGS_READ),
                    writable=bool(flags & _SECTION_FLAGS_WRITE),
                    executable=bool(flags & (_SECTION_FLAGS_EXEC | _SECTION_FLAGS_CODE)),
                    virtual_address=va,
                )
            )
            packer = PACKER_SECTIONS.get(name.lower())
            if packer and packer not in parsed.packers:
                parsed.packers.append(packer)

        parsed.entry_point = entry_rva
        if entry_rva:
            parsed.entry_section = self.section_of_rva(entry_rva)
            if parsed.entry_section is None:
                self.anomaly("entry point 0x%x không nằm trong section nào" % entry_rva)

        for step in (
            self.parse_imports,
            self.parse_delay_imports,
            self.parse_exports,
            self.parse_resources,
            self.parse_signature,
            self.parse_overlay,
            self.parse_clr,
        ):
            try:
                step()
            except (Truncated, ValueError, IndexError) as exc:
                self.anomaly("%s: %s" % (step.__name__.replace("parse_", "đọc "), exc))
        parsed.imphash = imphash(parsed.imports)

    # --- import / export -------------------------------------------------
    def _thunks(self, rva: int):
        offset = self.rva_to_offset(rva)
        if offset is None:
            return
        size = 8 if self.is64 else 4
        flag = 1 << 63 if self.is64 else 1 << 31
        for index in range(MAX_IMPORTS):
            at = offset + index * size
            if not self.view.has(at, size):
                return
            value = self.view.u64(at) if self.is64 else self.view.u32(at)
            if value == 0:
                return
            if value & flag:
                yield None, value & 0xFFFF
                continue
            name_offset = self.rva_to_offset(value & 0x7FFFFFFF)
            if name_offset is None:
                yield None, None
                continue
            yield self.view.cstr(name_offset + 2, 256), None

    def parse_imports(self) -> None:
        rva, size = self.directory(1)
        if not rva:
            return
        offset = self.rva_to_offset(rva)
        if offset is None:
            self.anomaly("bảng import trỏ ra ngoài tệp")
            return
        seen_libraries: Set[str] = set()
        for index in range(MAX_IMPORT_DLLS):
            at = offset + index * 20
            if not self.view.has(at, 20):
                break
            lookup, _, _, name_rva, first_thunk = (
                self.view.u32(at + delta) for delta in (0, 4, 8, 12, 16)
            )
            if not (lookup or name_rva or first_thunk):
                break
            name_offset = self.rva_to_offset(name_rva)
            library = self.view.cstr(name_offset, 256) if name_offset is not None else "?"
            if library.lower() not in seen_libraries:
                seen_libraries.add(library.lower())
                self.parsed.libraries.append(library)
            for name, ordinal in self._thunks(lookup or first_thunk):
                if len(self.parsed.imports) >= MAX_IMPORTS:
                    self.anomaly("quá nhiều import, đã cắt ở %d" % MAX_IMPORTS)
                    return
                if name is None and ordinal is None:
                    continue
                self.parsed.imports.append(Import(library, name or "", ordinal))

    def parse_delay_imports(self) -> None:
        rva, _ = self.directory(13)
        if not rva:
            return
        offset = self.rva_to_offset(rva)
        if offset is None:
            return
        for index in range(MAX_IMPORT_DLLS):
            at = offset + index * 32
            if not self.view.has(at, 32):
                break
            attributes = self.view.u32(at)
            name_rva = self.view.u32(at + 4)
            names_rva = self.view.u32(at + 16)
            if not name_rva:
                break
            if not attributes & 1:  # dạng cũ lưu VA thay vì RVA
                name_rva -= self.image_base & 0xFFFFFFFF
                names_rva -= self.image_base & 0xFFFFFFFF
            name_offset = self.rva_to_offset(name_rva)
            library = self.view.cstr(name_offset, 256) if name_offset is not None else "?"
            if library not in self.parsed.libraries:
                self.parsed.libraries.append(library)
            for name, ordinal in self._thunks(names_rva):
                if len(self.parsed.imports) >= MAX_IMPORTS:
                    return
                if name is None and ordinal is None:
                    continue
                self.parsed.imports.append(Import(library, name or "", ordinal, delayed=True))

    def parse_exports(self) -> None:
        rva, _ = self.directory(0)
        if not rva:
            return
        offset = self.rva_to_offset(rva)
        if offset is None:
            return
        name_offset = self.rva_to_offset(self.view.u32(offset + 12))
        if name_offset is not None:
            self.parsed.metadata["export_name"] = self.view.cstr(name_offset, 256)
        count = min(self.view.u32(offset + 24), MAX_EXPORTS)
        names_offset = self.rva_to_offset(self.view.u32(offset + 32))
        if names_offset is None:
            return
        for index in range(count):
            at = names_offset + index * 4
            if not self.view.has(at, 4):
                break
            entry = self.rva_to_offset(self.view.u32(at))
            if entry is not None:
                self.parsed.exports.append(self.view.cstr(entry, 256))

    # --- resource --------------------------------------------------------
    def parse_resources(self) -> None:
        rva, _ = self.directory(2)
        if not rva:
            return
        base = self.rva_to_offset(rva)
        if base is None:
            self.anomaly("bảng resource trỏ ra ngoài tệp")
            return
        visited: Set[int] = set()
        self._walk_resources(base, base, 0, [], visited)

    def _resource_label(self, base: int, raw: int) -> str:
        if raw & 0x80000000:
            at = base + (raw & 0x7FFFFFFF)
            length = self.view.u16(at)
            return self.view.bytes_at(at + 2, min(length, 128) * 2).decode(
                "utf-16-le", errors="replace"
            )
        return str(raw & 0xFFFF)

    def _walk_resources(
        self, base: int, offset: int, depth: int, path: List[str], visited: Set[int]
    ) -> None:
        if depth > MAX_RESOURCE_DEPTH or offset in visited:
            if offset in visited:
                self.anomaly("cây resource có vòng lặp")
            return
        visited.add(offset)
        named = self.view.u16(offset + 12)
        ids = self.view.u16(offset + 14)
        for index in range(min(named + ids, MAX_RESOURCES)):
            if len(self.parsed.resources) >= MAX_RESOURCES:
                return
            at = offset + 16 + index * 8
            raw_name = self.view.u32(at)
            target = self.view.u32(at + 4)
            label = self._resource_label(base, raw_name)
            if target & 0x80000000:
                self._walk_resources(
                    base, base + (target & 0x7FFFFFFF), depth + 1, path + [label], visited
                )
                continue
            entry = base + target
            data_rva = self.view.u32(entry)
            size = self.view.u32(entry + 4)
            data_offset = self.rva_to_offset(data_rva)
            if data_offset is None:
                continue
            chunk = self.data[data_offset : data_offset + size]
            type_label = path[0] if path else label
            if type_label.isdigit():
                type_label = _RESOURCE_TYPES.get(int(type_label), type_label)
            name_label = path[1] if len(path) > 1 else label
            self.parsed.resources.append(
                Resource(type_label, name_label, len(chunk), shannon(chunk), data_offset)
            )
            if type_label == "VERSION" and "CompanyName" not in self.parsed.metadata:
                self.parsed.metadata.update(parse_version_info(chunk))

    # --- chữ ký Authenticode ---------------------------------------------
    def parse_signature(self) -> None:
        offset, size = self.directory(4)  # riêng mục này là offset tệp, không phải RVA
        if not offset or not size:
            return
        if not self.view.has(offset, 8):
            self.anomaly("bảng chứng chỉ trỏ ra ngoài tệp")
            return
        cert_type = self.view.u16(offset + 6)
        blob = self.data[offset + 8 : offset + min(size, 1 << 20)]
        self.parsed.metadata["_signature_range"] = "%d:%d" % (offset, offset + size)
        self.parsed.signature = Signature(
            present=True,
            kind="Authenticode ( PKCS#7 )" if cert_type == 2 else "WIN_CERTIFICATE loại %d" % cert_type,
            signer_hints=certificate_names(blob),
        )

    # --- overlay ---------------------------------------------------------
    def parse_overlay(self) -> None:
        end = 0
        for _, _, raw_ptr, raw_size, _ in self.sections:
            if raw_size:
                end = max(end, self.raw_pointer(raw_ptr) + raw_size)
        if not end or end >= len(self.data):
            return
        cert_offset, cert_size = self.directory(4)
        stop = len(self.data)
        if cert_offset and cert_offset >= end and cert_offset + cert_size >= stop - 8:
            stop = cert_offset  # chứng chỉ nằm cuối tệp là chuyện bình thường
        size = stop - end
        if size <= 0:
            return
        chunk = self.data[end:stop]
        kind = ""
        head = chunk[:64]
        for magic, label in _OVERLAY_SIGNATURES:
            if magic in head:
                kind = label
                break
        if not kind and b"Nullsoft" in self.data[:8192]:
            kind = "trình cài đặt NSIS"
        self.parsed.overlay = Overlay(end, size, shannon(chunk), kind)

    # --- .NET ------------------------------------------------------------
    def parse_clr(self) -> None:
        rva, size = self.directory(14)
        if not rva:
            return
        offset = self.rva_to_offset(rva)
        if offset is None:
            self.anomaly("header CLR trỏ ra ngoài tệp")
            return
        self.parsed.traits.append(".net")
        meta_rva = self.view.u32(offset + 8)
        meta_size = self.view.u32(offset + 12)
        flags = self.view.u32(offset + 16)
        if flags & 0x1 == 0:
            self.parsed.traits.append("mixed-mode")
        meta_offset = self.rva_to_offset(meta_rva)
        if meta_offset is None:
            self.anomaly("metadata .NET trỏ ra ngoài tệp")
            return
        dotnet.parse_metadata(self.data, meta_offset, meta_size, self.parsed)


def parse(data: bytes) -> Parsed:
    parsed = Parsed(format="PE", family="pe")
    _PE(data, parsed).parse()
    return parsed


def imphash(imports: List[Import]) -> str:
    """imphash kiểu Mandiant: md5 của "thư-viện.hàm" viết thường, giữ thứ tự.

    Import theo ordinal được băm thành ``ordN``, nên với ws2_32 / oleaut32 kết
    quả có thể khác pefile ( pefile tra bảng ordinal -> tên cho hai thư viện đó ).
    """
    parts = []
    for item in imports:
        if item.delayed:
            continue
        library = item.library.lower()
        for suffix in (".dll", ".ocx", ".sys"):
            if library.endswith(suffix):
                library = library[: -len(suffix)]
                break
        name = item.name.lower() if item.name else "ord%d" % (item.ordinal or 0)
        parts.append("%s.%s" % (library, name))
    if not parts:
        return ""
    return hashlib.md5(",".join(parts).encode("utf-8"), usedforsecurity=False).hexdigest()  # type: ignore[call-arg]


def parse_version_info(chunk: bytes) -> Dict[str, str]:
    """Rút cặp khoá/giá trị của StringFileInfo trong resource VERSION."""
    result: Dict[str, str] = {}
    try:
        text = chunk.decode("utf-16-le", errors="replace")
    except Exception:  # pragma: no cover - errors="replace" không ném
        return result
    for key in _VERSION_KEYS:
        position = text.find(key + "\x00")
        if position < 0:
            continue
        cursor = position + len(key) + 1
        while cursor < len(text) and text[cursor] == "\x00":
            cursor += 1
        end = text.find("\x00", cursor)
        value = text[cursor : end if end >= 0 else cursor + 128][:128].strip()
        if value and value.isprintable():
            result[key] = value
    return result


_CN_OID = b"\x06\x03\x55\x04\x03"  # 2.5.4.3 commonName
_O_OID = b"\x06\x03\x55\x04\x0a"  # 2.5.4.10 organizationName


def certificate_names(blob: bytes) -> List[str]:
    """Tên CN / O xuất hiện trong khối PKCS#7. CHỈ là gợi ý: không kiểm chuỗi
    tin cậy, không kiểm chữ ký có khớp nội dung tệp hay không."""
    names: List[str] = []
    for oid in (_CN_OID, _O_OID):
        start = 0
        while len(names) < 12:
            position = blob.find(oid, start)
            if position < 0:
                break
            start = position + len(oid)
            if start + 2 > len(blob):
                break
            tag, length = blob[start], blob[start + 1]
            if tag in (0x0C, 0x13, 0x14, 0x16, 0x1E) and length < 0x80:
                raw = blob[start + 2 : start + 2 + length]
                value = raw.decode("utf-16-be" if tag == 0x1E else "utf-8", errors="replace")
                if value and value not in names:
                    names.append(value)
    return names


_SAFE_NAME = re.compile(r"^[\x20-\x7e]{1,8}$")


def odd_section_names(parsed: Parsed) -> List[str]:
    return [section.name for section in parsed.sections if not _SAFE_NAME.match(section.name)]
