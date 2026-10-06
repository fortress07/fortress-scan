"""Tệp thực thi dạng kho ZIP: Java .jar / .war, Python zipapp .pyz, Android .apk.

Đọc bằng zipfile của thư viện chuẩn, CHỈ trong bộ nhớ và có trần: số mục,
số byte giải nén mỗi mục, tổng số byte giải nén và tỉ lệ nén ( zip bomb ).
Không giải nén ra đĩa, không nạp class, không chạy gì.
"""

from __future__ import annotations

import io
import zipfile
from typing import List

from ..model import Parsed
from ..reader import ByteView, Truncated

MAX_MEMBERS = 20_000
MAX_MEMBER_BYTES = 4 << 20
MAX_TOTAL_BYTES = 64 << 20
MAX_RATIO = 200
MAX_CLASS_STRINGS = 200_000

TEXT_SUFFIXES = (".py", ".txt", ".html", ".hta", ".ps1", ".bat", ".cmd", ".sh", ".js", ".vbs", ".properties", ".json", ".xml", ".mf")


def looks_like(data: bytes) -> bool:
    return data[:4] == b"PK\x03\x04"


def parse(data: bytes, name: str = "") -> Parsed:
    parsed = Parsed(format="ZIP", family="zip")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError) as exc:
        parsed.anomalies.append("kho ZIP hỏng: %s" % exc)
        return parsed
    with archive:
        members = archive.infolist()
        names = [member.filename for member in members[:MAX_MEMBERS]]
        lowered = name.lower()
        if "META-INF/MANIFEST.MF" in names or any(n.endswith(".class") for n in names[:2000]):
            parsed.format = "Java archive ( JAR )"
            parsed.family = "jar"
            parsed.traits.append("java")
        if "classes.dex" in names or lowered.endswith(".apk"):
            parsed.format = "Android package ( APK )"
            parsed.traits.append("android")
        if "__main__.py" in names or lowered.endswith(".pyz"):
            parsed.format = "Python zipapp"
            parsed.traits.append("python")
        if len(members) > MAX_MEMBERS:
            parsed.anomalies.append("kho có %d mục, chỉ đọc %d mục đầu" % (len(members), MAX_MEMBERS))
        parsed.metadata["members"] = str(len(members))
        total = 0
        class_strings = 0
        encrypted = 0
        for member in members[:MAX_MEMBERS]:
            if member.is_dir():
                continue
            parsed.names.append((member.filename, "tên mục trong kho"))
            if member.flag_bits & 0x1:
                encrypted += 1
                continue
            lower = member.filename.lower()
            wanted = lower.endswith(".class") or lower.endswith(TEXT_SUFFIXES) or lower.endswith(".dex")
            if not wanted:
                continue
            if member.file_size > MAX_MEMBER_BYTES:
                parsed.anomalies.append("bỏ qua mục quá lớn: %s" % member.filename[:120])
                continue
            if member.compress_size and member.file_size / member.compress_size > MAX_RATIO:
                parsed.anomalies.append("bỏ qua mục có tỉ lệ nén bất thường ( zip bomb ? ): %s" % member.filename[:120])
                continue
            if total + member.file_size > MAX_TOTAL_BYTES:
                parsed.anomalies.append("đã chạm trần tổng dung lượng giải nén, phần còn lại không được đọc")
                break
            try:
                with archive.open(member) as handle:
                    body = handle.read(MAX_MEMBER_BYTES + 1)[:MAX_MEMBER_BYTES]
            except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError, EOFError) as exc:
                parsed.anomalies.append("không đọc được %s: %s" % (member.filename[:120], exc))
                continue
            total += len(body)
            if lower.endswith(".class"):
                strings = class_constants(body)
                class_strings += len(strings)
                if class_strings > MAX_CLASS_STRINGS:
                    parsed.anomalies.append("quá nhiều hằng trong class, phần còn lại không được đọc")
                    break
                parsed.embedded_text.append((member.filename, "\n".join(strings)))
            elif lower.endswith(".dex"):
                parsed.embedded.append((member.filename, body))
            else:
                text = body.decode("utf-8", errors="replace")
                parsed.embedded_text.append((member.filename, text))
                if lower == "meta-inf/manifest.mf":
                    for line in text.splitlines():
                        if line.lower().startswith("main-class:"):
                            parsed.metadata["main_class"] = line.split(":", 1)[1].strip()[:200]
        if encrypted:
            parsed.traits.append("encrypted-members")
            parsed.anomalies.append("%d mục được mã hoá bằng mật khẩu, không xem được bên trong" % encrypted)
        if any(n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC")) for n in names):
            parsed.signature.present = True
            parsed.signature.kind = "chữ ký JAR ( META-INF ), chưa kiểm"
    return parsed


def class_constants(body: bytes) -> List[str]:
    """Các hằng Utf8 trong constant pool của một tệp .class ( JVMS §4.4 )."""
    view = ByteView(body, little=False)
    found: List[str] = []
    try:
        if view.u32(0) != 0xCAFEBABE:
            return found
        count = view.u16(8)
        cursor = 10
        index = 1
        while index < count:
            tag = view.u8(cursor)
            if tag == 1:
                length = view.u16(cursor + 1)
                raw = view.bytes_at(cursor + 3, length)
                found.append(raw.decode("utf-8", errors="replace"))
                cursor += 3 + length
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                cursor += 5
            elif tag in (5, 6):
                cursor += 9
                index += 1  # long / double chiếm hai ô
            elif tag in (7, 8, 16, 19, 20):
                cursor += 3
            elif tag == 15:
                cursor += 4
            else:
                break
            index += 1
    except Truncated:
        pass
    return found
