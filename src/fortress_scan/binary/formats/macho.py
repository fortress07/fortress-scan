"""Parser Mach-O ( macOS, iOS ) và Universal / fat binary, chỉ đọc."""

from __future__ import annotations

from typing import List

from ..entropy import shannon
from ..model import Import, Parsed, Section, Signature
from ..reader import ByteView, Truncated
from .pe import certificate_names

MAX_COMMANDS = 1024
MAX_FAT_ARCHES = 16
MAX_SYMBOLS = 50_000

_THIN = {
    0xFEEDFACE: (False, True),  # (64 bit, little-endian khi đọc LE)
    0xFEEDFACF: (True, True),
    0xCEFAEDFE: (False, False),
    0xCFFAEDFE: (True, False),
}

_CPU = {
    7: "x86",
    0x01000007: "x86-64",
    12: "ARM",
    0x0100000C: "ARM64",
    0x0200000C: "ARM64_32",
    18: "PowerPC",
    0x01000012: "PowerPC64",
}

_FILETYPES = {
    1: "object",
    2: "executable",
    6: "dylib",
    7: "dyld",
    8: "bundle",
    11: "kext",
}

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_MAIN = 0x80000028
LC_RPATH = 0x8000001C


def looks_like(data: bytes) -> bool:
    if len(data) < 8:
        return False
    magic = int.from_bytes(data[:4], "little")
    if magic in _THIN:
        return True
    return is_fat(data)


def is_fat(data: bytes) -> bool:
    """CAFEBABE dùng chung cho fat Mach-O và tệp .class của Java; fat binary có
    số kiến trúc nhỏ, còn .class đặt số phiên bản lớp ( >= 45 ) ở cùng vị trí."""
    if data[:4] not in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        return False
    count = int.from_bytes(data[4:8], "big")
    return 0 < count <= MAX_FAT_ARCHES


def parse(data: bytes) -> Parsed:
    if is_fat(data):
        return _parse_fat(data)
    parsed = Parsed(format="Mach-O", family="macho")
    _parse_thin(data, 0, parsed)
    return parsed


def _parse_fat(data: bytes) -> Parsed:
    parsed = Parsed(format="Mach-O universal", family="macho")
    view = ByteView(data, little=False)
    wide = data[3] == 0xBF
    count = min(view.u32(4), MAX_FAT_ARCHES)
    entry = 32 if wide else 20
    arches: List[str] = []
    for index in range(count):
        at = 8 + index * entry
        try:
            cpu = view.u32(at)
            if wide:
                offset, size = view.u64(at + 8), view.u64(at + 16)
            else:
                offset, size = view.u32(at + 8), view.u32(at + 12)
        except Truncated:
            parsed.anomalies.append("bảng kiến trúc của fat binary bị cắt cụt")
            break
        arches.append(_CPU.get(cpu, "cpu 0x%x" % cpu))
        if offset + size > len(data):
            parsed.anomalies.append("lát kiến trúc %d vượt cuối tệp" % index)
            continue
        child = Parsed(format="Mach-O", family="macho")
        _parse_thin(data[offset : offset + size], offset, child)
        parsed.children.append(child)
    parsed.arch = ", ".join(arches)
    # Gộp import / thư viện của các lát để detector nhìn một lần.
    for child in parsed.children:
        for item in child.imports:
            if item not in parsed.imports:
                parsed.imports.append(item)
        for library in child.libraries:
            if library not in parsed.libraries:
                parsed.libraries.append(library)
        parsed.sections.extend(child.sections)
        parsed.anomalies.extend(a for a in child.anomalies if a not in parsed.anomalies)
        for trait in child.traits:
            if trait not in parsed.traits:
                parsed.traits.append(trait)
        if child.signature.present:
            parsed.signature = child.signature
        parsed.metadata.update({k: v for k, v in child.metadata.items() if k not in parsed.metadata})
    return parsed


def _parse_thin(data: bytes, base: int, parsed: Parsed) -> None:
    magic = int.from_bytes(data[:4], "little")
    if magic not in _THIN:
        parsed.anomalies.append("lát Mach-O không có magic hợp lệ")
        return
    is64, little = _THIN[magic]
    view = ByteView(data, little=little)
    try:
        cpu = view.u32(4)
        filetype = view.u32(12)
        ncmds = view.u32(16)
        flags = view.u32(24)
    except Truncated:
        parsed.anomalies.append("header Mach-O bị cắt cụt")
        return
    parsed.format = "Mach-O 64-bit" if is64 else "Mach-O 32-bit"
    parsed.arch = _CPU.get(cpu, "cpu 0x%x" % cpu)
    parsed.metadata["macho_type"] = _FILETYPES.get(filetype, "type %d" % filetype)
    if filetype == 6:
        parsed.traits.append("dll")
    if not flags & 0x200000 and filetype == 2:  # MH_PIE
        parsed.traits.append("no-aslr")
    cursor = 32 if is64 else 28
    if ncmds > MAX_COMMANDS:
        parsed.anomalies.append("header khai %d load command, đã cắt" % ncmds)
        ncmds = MAX_COMMANDS
    for _ in range(ncmds):
        try:
            cmd = view.u32(cursor)
            size = view.u32(cursor + 4)
        except Truncated:
            parsed.anomalies.append("load command bị cắt cụt")
            return
        if size < 8:
            parsed.anomalies.append("load command có kích thước %d không hợp lệ" % size)
            return
        try:
            _command(data, view, base, cursor, cmd, size, is64, parsed)
        except Truncated as exc:
            parsed.anomalies.append("load command 0x%x: %s" % (cmd, exc))
        cursor += size


def _command(data, view, base, cursor, cmd, size, is64, parsed: Parsed) -> None:
    if cmd in (LC_SEGMENT, LC_SEGMENT_64):
        segname = view.fixed_str(cursor + 8, 16)
        if is64:
            fileoff, filesize = view.u64(cursor + 40), view.u64(cursor + 48)
            maxprot, initprot, nsects = view.u32(cursor + 56), view.u32(cursor + 60), view.u32(cursor + 64)
            header, section_size = 72, 80
        else:
            fileoff, filesize = view.u32(cursor + 32), view.u32(cursor + 36)
            maxprot, initprot, nsects = view.u32(cursor + 40), view.u32(cursor + 44), view.u32(cursor + 48)
            header, section_size = 56, 68
        # Tệp object ( MH_OBJECT ) luôn có một segment rwx vô danh; chỉ ảnh
        # chạy được hoặc thư viện mới đáng xét.
        if initprot & 0x2 and initprot & 0x4 and parsed.metadata.get("macho_type") != "object":
            parsed.traits.append("wx-segment:%s" % (segname or "?"))
        del maxprot
        for index in range(min(nsects, 256)):
            at = cursor + header + index * section_size
            if not view.has(at, section_size):
                break
            sectname = view.fixed_str(at, 16)
            if is64:
                addr, sect_size, offset = view.u64(at + 32), view.u64(at + 40), view.u32(at + 48)
            else:
                addr, sect_size, offset = view.u32(at + 32), view.u32(at + 36), view.u32(at + 40)
            body = data[offset : offset + sect_size] if offset else b""
            parsed.sections.append(
                Section(
                    name="%s,%s" % (segname, sectname),
                    offset=base + offset,
                    raw_size=len(body),
                    virtual_size=sect_size,
                    entropy=shannon(body),
                    writable=bool(initprot & 0x2) and parsed.metadata.get("macho_type") != "object",
                    executable=bool(initprot & 0x4),
                    virtual_address=addr,
                )
            )
            if sectname in ("__gopclntab", "__go_buildinfo") and "go" not in parsed.traits:
                parsed.traits.append("go")
        if segname.upper().startswith("UPX") or segname == "__XHDR":
            if "UPX" not in parsed.packers:
                parsed.packers.append("UPX")
        del fileoff, filesize
    elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
        name_offset = view.u32(cursor + 8)
        library = view.cstr(cursor + name_offset, min(size, 512))
        if library not in parsed.libraries:
            parsed.libraries.append(library)
    elif cmd == LC_SYMTAB:
        symoff, nsyms, stroff = view.u32(cursor + 8), view.u32(cursor + 12), view.u32(cursor + 16)
        entry = 16 if is64 else 12
        for index in range(min(nsyms, MAX_SYMBOLS)):
            at = symoff + index * entry
            if not view.has(at, entry):
                break
            strx = view.u32(at)
            n_type = view.u8(at + 4)
            if n_type & 0xE0:  # mục debug ( stab )
                continue
            try:
                name = view.cstr(stroff + strx, 256)
            except Truncated:
                continue
            if not name:
                continue
            # Mach-O thêm tiền tố "_" vào mọi ký hiệu C; bỏ nó ở CẢ import và
            # export để tên trùng với bảng năng lực và với tên trong ELF.
            plain = name[1:] if name.startswith("_") else name
            if n_type & 0x0E == 0 and n_type & 0x01:
                parsed.imports.append(Import("", plain))
            elif n_type & 0x0E == 0x0E and n_type & 0x01:
                parsed.exports.append(plain)
    elif cmd == LC_CODE_SIGNATURE:
        dataoff, datasize = view.u32(cursor + 8), view.u32(cursor + 12)
        blob = data[dataoff : dataoff + min(datasize, 1 << 20)]
        parsed.metadata["_signature_range"] = "%d:%d" % (base + dataoff, base + dataoff + datasize)
        hints = certificate_names(blob)
        parsed.signature = Signature(
            present=True,
            kind="Apple code signature" + ("" if hints else " ( không thấy chứng chỉ, có thể ad-hoc )"),
            signer_hints=hints,
        )
    elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
        if view.u32(cursor + 16):
            parsed.traits.append("fairplay-encrypted")
    elif cmd == LC_MAIN:
        parsed.entry_point = view.u64(cursor + 8)
