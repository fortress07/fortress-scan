"""Điều phối một lượt phân tích: nhận diện định dạng, parse, rút chuỗi, chạy
detector, chấm kết luận. Chỉ ĐỌC tệp; không ghi, không nạp, không chạy."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from ..security import paths as safe_paths
from . import deobfuscate, detectors, reference, scoring
from .formats import archive, elf, embedded, macho, pe, scripts
from .model import Parsed, Tier, TriageReport, Verdict
from .strings import StringPool, add_text, extract

DEFAULT_MAX_BYTES = 256 << 20
MAX_DIRECTORY_FILES = 20_000
_IDENTIFIER = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{2,63}")


def identify(data: bytes, name: str) -> Tuple[str, Optional[str]]:
    """(họ định dạng, nhãn ngôn ngữ script nếu là script)."""
    if pe.looks_like(data):
        return "pe", None
    if elf.looks_like(data):
        return "elf", None
    if macho.looks_like(data):
        return "macho", None
    if data[:4] == b"\xca\xfe\xba\xbe":
        return "class", None
    if archive.looks_like(data):
        return "zip", None
    language = scripts.script_type(name, data[:256])
    if language:
        return "script", language
    return "unknown", None


def _parse(family: str, data: bytes, name: str, language: Optional[str]) -> Parsed:
    if family == "pe":
        return pe.parse(data)
    if family == "elf":
        return elf.parse(data)
    if family == "macho":
        return macho.parse(data)
    if family == "zip":
        return archive.parse(data, name)
    if family == "class":
        parsed = Parsed(format="Java class", family="jar", traits=["java"])
        parsed.embedded_text.append((name or "class", "\n".join(archive.class_constants(data))))
        return parsed
    if family == "script":
        return scripts.parse(data, name, language or "shell")
    return Parsed(format="không nhận ra định dạng", family="unknown")


def _build_pool(parsed: Parsed, data: bytes) -> StringPool:
    pool = StringPool()
    if parsed.family in ("pe", "elf", "macho", "unknown"):
        extract(data, pool)
    for label, text in parsed.embedded_text:
        add_text(text, pool, label + ":text")
    for label, blob in parsed.embedded:
        extract(blob, pool, base_label=label, base_offset=-1)
        if label.startswith("PyInstaller script"):
            for token in set(_IDENTIFIER.findall(blob)):
                parsed.names.append((token.decode("ascii"), label))
    if parsed.family in ("jar", "zip"):
        for name, source in parsed.names:
            if source == "tên mục trong kho":
                pool.add(name, -1, "tên mục trong kho")
    _recover_hidden_strings(parsed, data, pool)
    return pool


def _recover_hidden_strings(parsed: Parsed, data: bytes, pool: StringPool) -> None:
    """Chuỗi bị che bằng XOR một byte: giải ra rồi đổ vào cùng một bể.

    Đổ chung bể là có chủ ý: cả 39 dấu hiệu chạy lại trên phần vừa giải mà
    không phải viết riêng đường nào, còn nhãn `xor:0x..` giữ cho báo cáo nói
    rõ chuỗi này không nằm lộ thiên.
    """
    if parsed.family not in ("pe", "elf", "macho", "script", "unknown"):
        return
    try:
        recovered = deobfuscate.recover(data)
    except Exception as exc:  # một tệp thù địch không được làm chết cả lượt
        parsed.anomalies.append("deobfuscate: %s: %s" % (type(exc).__name__, exc))
        return
    notes = []
    for key, start, blob, anchor in recovered:
        label = "xor:0x%02x" % key
        extract(blob, pool, base_label=label, base_offset=start)
        notes.append("%s tại offset 0x%x ( trúng mỏ neo %s )"
                     % (label, start, anchor.decode("utf-16-le" if b"\x00" in anchor else "ascii")))
    if notes:
        parsed.metadata["_xor_recovered"] = " | ".join(notes)


def analyze_bytes(data: bytes, name: str = "", truncated: bool = False) -> TriageReport:
    family, language = identify(data, name)
    try:
        parsed = _parse(family, data, name, language)
    except Exception as exc:  # parser gặp tệp thù địch: báo, không chết cả lượt
        parsed = Parsed(format=family, family=family if family != "class" else "jar")
        parsed.anomalies.append("parser dừng giữa chừng: %s: %s" % (type(exc).__name__, exc))
    if parsed.family in ("pe", "elf", "macho"):
        for step in (embedded.pyinstaller, embedded.go_buildinfo):
            try:
                step(data, parsed)
            except Exception as exc:
                parsed.anomalies.append("%s: %s" % (step.__name__, exc))
    pool = _build_pool(parsed, data)
    context = detectors.Context(parsed, pool, data)
    detectors.run_all(context)
    _go_tls_demotion(context)
    hits = sorted(context.hits, key=lambda hit: (-int(hit.tier), -hit.spec.weight, hit.spec.id))
    verdict, found = scoring.verdict_for(hits)
    limited = scoring.visibility_limited(hits, parsed)
    limitations = _limitations(parsed, limited, truncated, pool)
    confidence_prefix = ""
    if parsed.family in ("script", "unknown") and verdict > Verdict.SUSPICIOUS:
        why = reference.looks_like_reference(pool)
        if why is not None:
            verdict = Verdict.SUSPICIOUS
            confidence_prefix = (
                "Kết luận đã bị CHẶN TRẦN ở mức này vì tệp trông như tài liệu hoặc bộ quy tắc "
                "phát hiện ( %s ) chứ không phải tệp tấn công. Mọi dấu hiệu vẫn được liệt kê đầy "
                "đủ bên dưới: nếu đây KHÔNG phải tài liệu, hãy đọc từng dấu hiệu và tự đánh giá "
                "lại. " % why
            )
            context.notes.append(
                "đã chặn trần kết luận: tệp mang %s, nên các chuỗi đặc trưng trong đó có thể là "
                "nội dung mô tả tấn công chứ không phải lệnh được chạy" % why
            )
            limitations.append(
                "Tệp được xem là tài liệu / bộ quy tắc phát hiện, nên kết luận bị chặn ở mức "
                "'đáng ngờ'. Phép chặn này chỉ áp cho script và tệp văn bản, không áp cho tệp "
                "thực thi đã biên dịch."
            )
    hashes = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),  # type: ignore[call-arg]
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),  # type: ignore[call-arg]
    }
    if parsed.imphash:
        hashes["imphash"] = parsed.imphash
    reasons = [scoring.pillar_text(name) + " ( %s )" % ", ".join(ids) for name, ids in found.items()]
    report = TriageReport(
        path=name,
        size=len(data),
        hashes=hashes,
        parsed=parsed,
        hits=hits,
        verdict=verdict,
        score=scoring.score_for(verdict, hits),
        confidence=confidence_prefix + scoring.confidence_for(verdict, found, limited),
        reasons=reasons,
        limitations=limitations,
        iocs=context.iocs,
        guidance=scoring.guidance_for(verdict),
        truncated=truncated,
        notes=context.notes,
        pool=pool,
    )
    return report


def _go_tls_demotion(context: detectors.Context) -> None:
    """Chương trình Go dùng HTTPS kéo crypto/aes vào qua crypto/tls. Khi đó
    "có AES" không nói lên điều gì về ý định mã hoá tệp, nên hạ chuỗi C04."""
    if not context.parsed.has_trait("go"):
        return
    if "crypto/tls." not in context.pool.lower:
        return
    evidence = context.capabilities.evidence("symmetric") + context.capabilities.evidence("asymmetric")
    if not evidence:
        return
    # Mã hoá của thư viện chuẩn ( kể cả bản golang.org/x/crypto vendored trong
    # stdlib ) thì giải thích được bằng TLS; thư viện bên thứ ba thì không.
    third_party = re.compile(r"(?<!vendor/)golang\.org/x/crypto|github\.com/[^\s|]{1,80}crypt")
    if not any(third_party.search(item.detail.lower()) for item in evidence):
        for hit in context.hits:
            if hit.spec.id == "FSX-C04":
                hit.tier_override = Tier.CONTEXT
                context.notes.append(
                    "chuỗi năng lực FSX-C04 bị hạ xuống bối cảnh: mã hoá duy nhất thấy được là của "
                    "thư viện chuẩn Go, vốn được crypto/tls kéo vào cho kết nối HTTPS"
                )


def _limitations(parsed: Parsed, limited: List[str], truncated: bool, pool: StringPool) -> List[str]:
    notes = [
        "Phân tích TĨNH: không chạy tệp, nên không thấy hành vi chỉ lộ ra lúc chạy "
        "( tải payload từ mạng, giải mã trong bộ nhớ, tham số dòng lệnh ).",
    ]
    if limited:
        notes.append("Tầm nhìn bị hạn chế bởi: %s." % ", ".join(limited))
    if truncated:
        notes.append("Tệp lớn hơn trần đọc, chỉ phần đầu được phân tích.")
    if pool.truncated:
        notes.append("Tệp có quá nhiều chuỗi, phần sau bị bỏ qua.")
    if parsed.family == "unknown":
        notes.append("Không nhận ra định dạng; chỉ có phân tích chuỗi thô.")
    if parsed.has_trait(".net"):
        notes.append("Với .NET, chỉ đọc định danh và chuỗi literal trong metadata; không dịch ngược IL.")
    if parsed.family in ("pe", "elf", "macho"):
        notes.append("Không dịch ngược lệnh máy ( disassembly ); năng lực suy ra từ import, ký hiệu và chuỗi.")
    if parsed.has_trait("android"):
        notes.append("Với APK, chỉ đọc chuỗi trong classes.dex; không phân tích bytecode Dalvik.")
    return notes


def read_limited(path: Path, max_bytes: int) -> Tuple[bytes, bool]:
    with open(path, "rb") as handle:
        data = handle.read(max_bytes + 1)
    return data[:max_bytes], len(data) > max_bytes


def analyze_path(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> TriageReport:
    target = Path(path)
    data, truncated = read_limited(target, max_bytes)
    return analyze_bytes(data, str(target), truncated)


def _is_candidate(path: Path) -> bool:
    lowered = path.name.lower()
    if lowered.endswith(scripts.DIRECTORY_SCRIPT_SUFFIXES):
        return True
    if lowered.endswith((".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".so", ".dylib", ".jar", ".war", ".pyz", ".apk", ".elf", ".bin", ".msi")):
        return True
    try:
        with open(path, "rb") as handle:
            head = handle.read(256)
    except OSError:
        return False
    family, _ = identify(head, "")
    if family in ("pe", "elf", "macho"):
        return True
    if family == "script" and head.startswith(b"#!"):
        return True
    return False


def discover(root: str, max_files: int = MAX_DIRECTORY_FILES) -> Iterator[Path]:
    """Duyệt thư mục, không đi theo liên kết, chỉ trả về tệp trông như thực thi."""
    base = Path(root)
    if base.is_file():
        yield base
        return
    count = 0
    stack = [base]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda entry: entry.name)
        except OSError:
            continue
        for entry in entries:
            path = Path(entry.path)
            if safe_paths.is_link_like(path):
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in (".git", ".hg", ".svn", "__pycache__"):
                        stack.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if _is_candidate(path):
                count += 1
                yield path
                if count >= max_files:
                    return
