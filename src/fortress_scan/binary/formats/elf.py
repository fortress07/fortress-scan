"""Parser ELF ( Linux, BSD, ESXi ) thuần Python, chỉ đọc."""

from __future__ import annotations

from typing import List, Optional, Tuple

from ..entropy import shannon
from ..model import Import, Parsed, Section
from ..reader import ByteView, Truncated

MAX_SECTIONS = 512
MAX_SEGMENTS = 256
MAX_SYMBOLS = 50_000

_MACHINES = {
    0x03: "x86",
    0x3E: "x86-64",
    0x28: "ARM",
    0xB7: "ARM64",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x15: "PowerPC64",
    0xF3: "RISC-V",
    0x2B: "SPARC v9",
    0x16: "s390",
}

_TYPES = {1: "relocatable", 2: "executable", 3: "shared object / PIE", 4: "core dump"}

SHT_SYMTAB = 2
SHT_DYNAMIC = 6
SHT_DYNSYM = 11
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
DT_NEEDED = 1
DT_STRTAB = 5


def looks_like(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


class _ELF:
    def __init__(self, data: bytes, parsed: Parsed) -> None:
        self.data = data
        self.parsed = parsed
        self.is64 = data[4:5] == b"\x02"
        self.view = ByteView(data, little=data[5:6] != b"\x02")
        self.segments: List[Tuple[int, int, int, int, int]] = []  # type, offset, vaddr, filesz, flags
        self.section_rows: List[Tuple[str, int, int, int, int, int, int]] = []

    def anomaly(self, message: str) -> None:
        if message not in self.parsed.anomalies and len(self.parsed.anomalies) < 64:
            self.parsed.anomalies.append(message)

    def word(self, offset: int) -> int:
        return self.view.u64(offset) if self.is64 else self.view.u32(offset)

    def parse(self) -> None:
        view = self.view
        parsed = self.parsed
        parsed.format = "ELF64" if self.is64 else "ELF32"
        if self.data[4:5] not in (b"\x01", b"\x02") or self.data[5:6] not in (b"\x01", b"\x02"):
            self.anomaly("e_ident khai class / byte order không hợp lệ")
        e_type = view.u16(16)
        machine = view.u16(18)
        parsed.arch = _MACHINES.get(machine, "machine 0x%x" % machine)
        parsed.metadata["elf_type"] = _TYPES.get(e_type, "type %d" % e_type)
        parsed.metadata["byte_order"] = "little-endian" if view.little else "big-endian"
        if self.is64:
            entry, phoff, shoff = view.u64(24), view.u64(32), view.u64(40)
            phentsize, phnum = view.u16(54), view.u16(56)
            shentsize, shnum, shstrndx = view.u16(58), view.u16(60), view.u16(62)
        else:
            entry, phoff, shoff = view.u32(24), view.u32(28), view.u32(32)
            phentsize, phnum = view.u16(42), view.u16(44)
            shentsize, shnum, shstrndx = view.u16(46), view.u16(48), view.u16(50)
        parsed.entry_point = entry
        self._segments(phoff, phentsize, min(phnum, MAX_SEGMENTS))
        self._sections(shoff, shentsize, min(shnum, MAX_SECTIONS), shstrndx)
        if not self.section_rows and e_type in (2, 3):
            # Header section là tuỳ chọn khi chạy; packer như UPX xoá nó đi.
            parsed.traits.append("no-section-headers")
            self.anomaly("không có bảng section ( thường gặp ở tệp đã bị pack hoặc strip mạnh )")
            self._segment_view()
        for step in (self._symbols, self._needed):
            try:
                step()
            except (Truncated, ValueError, IndexError) as exc:
                self.anomaly("đọc ELF: %s" % exc)
        if not any(row[2] == SHT_SYMTAB for row in self.section_rows) and self.section_rows:
            parsed.traits.append("stripped")
        if entry and self.section_rows:
            for name, _, _, _, size, addr, _ in self.section_rows:
                if addr and addr <= entry < addr + size:
                    parsed.entry_section = name
                    break

    def _segments(self, phoff: int, phentsize: int, phnum: int) -> None:
        if not phoff or phentsize < (56 if self.is64 else 32):
            return
        view = self.view
        for index in range(phnum):
            at = phoff + index * phentsize
            if not view.has(at, phentsize):
                self.anomaly("bảng program header bị cắt cụt")
                break
            p_type = view.u32(at)
            if self.is64:
                flags = view.u32(at + 4)
                offset, vaddr, filesz = view.u64(at + 8), view.u64(at + 16), view.u64(at + 32)
            else:
                offset, vaddr, filesz = view.u32(at + 4), view.u32(at + 8), view.u32(at + 16)
                flags = view.u32(at + 24)
            self.segments.append((p_type, offset, vaddr, filesz, flags))
            if p_type == PT_INTERP:
                try:
                    self.parsed.metadata["interpreter"] = view.cstr(offset, 256)
                except Truncated:
                    self.anomaly("PT_INTERP trỏ ra ngoài tệp")
            if p_type == PT_GNU_STACK and flags & 0x1:
                self.parsed.traits.append("executable-stack")
        if self.segments and not any(seg[0] == PT_INTERP for seg in self.segments):
            if any(seg[0] == PT_LOAD for seg in self.segments):
                self.parsed.traits.append("static")

    def _sections(self, shoff: int, shentsize: int, shnum: int, shstrndx: int) -> None:
        if not shoff or not shnum or shentsize < (64 if self.is64 else 40):
            return
        view = self.view
        raw = []
        for index in range(shnum):
            at = shoff + index * shentsize
            if not view.has(at, shentsize):
                self.anomaly("bảng section bị cắt cụt")
                break
            name_index = view.u32(at)
            sh_type = view.u32(at + 4)
            if self.is64:
                flags, addr = view.u64(at + 8), view.u64(at + 16)
                offset, size = view.u64(at + 24), view.u64(at + 32)
                link = view.u32(at + 40)
            else:
                flags, addr = view.u32(at + 8), view.u32(at + 12)
                offset, size = view.u32(at + 16), view.u32(at + 20)
                link = view.u32(at + 24)
            raw.append((name_index, sh_type, flags, addr, offset, size, link))
        names_offset = raw[shstrndx][4] if shstrndx < len(raw) else None
        for name_index, sh_type, flags, addr, offset, size, link in raw:
            name = ""
            if names_offset is not None:
                try:
                    name = view.cstr(names_offset + name_index, 128)
                except Truncated:
                    name = "?"
            self.section_rows.append((name, offset, sh_type, flags, size, addr, link))
            body = b"" if sh_type == 8 or not flags & SHF_ALLOC else self.data[offset : offset + size]
            if sh_type == 0:
                continue
            if offset + size > len(self.data) and sh_type != 8:
                self.anomaly("section %r khai dữ liệu vượt cuối tệp" % name)
            if flags & SHF_ALLOC:
                self.parsed.sections.append(
                    Section(
                        name=name,
                        offset=offset,
                        raw_size=0 if sh_type == 8 else size,
                        virtual_size=size,
                        entropy=shannon(body),
                        writable=bool(flags & SHF_WRITE),
                        executable=bool(flags & SHF_EXECINSTR),
                        virtual_address=addr,
                    )
                )
            if name == ".go.buildinfo" or name == ".gopclntab":
                if "go" not in self.parsed.traits:
                    self.parsed.traits.append("go")

    def _segment_view(self) -> None:
        for index, (p_type, offset, vaddr, filesz, flags) in enumerate(self.segments):
            if p_type != PT_LOAD:
                continue
            body = self.data[offset : offset + filesz]
            self.parsed.sections.append(
                Section(
                    name="LOAD[%d]" % index,
                    offset=offset,
                    raw_size=len(body),
                    virtual_size=filesz,
                    entropy=shannon(body),
                    readable=bool(flags & 0x4),
                    writable=bool(flags & 0x2),
                    executable=bool(flags & 0x1),
                    virtual_address=vaddr,
                )
            )

    def writable_executable_segments(self) -> List[int]:
        return [
            index
            for index, seg in enumerate(self.segments)
            if seg[0] == PT_LOAD and seg[4] & 0x1 and seg[4] & 0x2
        ]

    def _symbols(self) -> None:
        view = self.view
        entry_size = 24 if self.is64 else 16
        for name, offset, sh_type, _, size, _, link in self.section_rows:
            if sh_type not in (SHT_DYNSYM, SHT_SYMTAB):
                continue
            if link >= len(self.section_rows):
                continue
            strtab = self.section_rows[link][1]
            count = min(size // entry_size, MAX_SYMBOLS)
            for index in range(1, count):
                at = offset + index * entry_size
                if not view.has(at, entry_size):
                    break
                st_name = view.u32(at)
                if self.is64:
                    info, shndx = view.u8(at + 4), view.u16(at + 6)
                else:
                    info, shndx = view.u8(at + 12), view.u16(at + 14)
                if not st_name:
                    continue
                symbol = view.cstr(strtab + st_name, 256)
                binding = info >> 4
                kind = info & 0xF
                if shndx == 0 and sh_type == SHT_DYNSYM:
                    self.parsed.imports.append(Import("", symbol))
                elif sh_type == SHT_DYNSYM and binding in (1, 2) and kind in (1, 2):
                    self.parsed.exports.append(symbol)
                elif sh_type == SHT_SYMTAB and kind == 2:
                    self.parsed.names.append((symbol, "symtab"))
                if len(self.parsed.imports) + len(self.parsed.exports) > MAX_SYMBOLS:
                    return

    def _vaddr_to_offset(self, vaddr: int) -> Optional[int]:
        for p_type, offset, start, filesz, _ in self.segments:
            if p_type == PT_LOAD and start <= vaddr < start + filesz:
                return offset + (vaddr - start)
        return None

    def _needed(self) -> None:
        view = self.view
        dynamic = [seg for seg in self.segments if seg[0] == PT_DYNAMIC]
        if not dynamic:
            return
        _, offset, _, filesz, _ = dynamic[0]
        size = 16 if self.is64 else 8
        entries = []
        strtab_vaddr = None
        for index in range(min(filesz // size, 4096)):
            at = offset + index * size
            if not view.has(at, size):
                break
            tag, value = self.word(at), self.word(at + size // 2)
            if tag == 0:
                break
            if tag == DT_STRTAB:
                strtab_vaddr = value
            entries.append((tag, value))
        if strtab_vaddr is None:
            return
        strtab = self._vaddr_to_offset(strtab_vaddr)
        if strtab is None:
            return
        for tag, value in entries:
            if tag == DT_NEEDED:
                try:
                    library = view.cstr(strtab + value, 256)
                except Truncated:
                    continue
                if library not in self.parsed.libraries:
                    self.parsed.libraries.append(library)


def parse(data: bytes) -> Parsed:
    parsed = Parsed(format="ELF", family="elf")
    elf = _ELF(data, parsed)
    try:
        elf.parse()
    except (Truncated, ValueError, IndexError) as exc:
        elf.anomaly("header ELF hỏng: %s" % exc)
    for index in elf.writable_executable_segments():
        parsed.traits.append("wx-segment:%d" % index)
    return parsed
