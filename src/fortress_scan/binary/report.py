"""Trình bày kết quả phân tích file thực thi: console, JSON, Markdown."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Sequence

from ..security.text import display_path, neutralize
from .model import IndicatorHit, Tier, TriageReport, Verdict

SCHEMA_VERSION = 1

_ICONS = {
    Verdict.NONE: "OK",
    Verdict.LOW: "LOW",
    Verdict.SUSPICIOUS: "SUSP",
    Verdict.LIKELY: "LIKELY",
    Verdict.HIGH: "HIGH",
}
_COLORS = {
    Verdict.NONE: "\x1b[32m",
    Verdict.LOW: "\x1b[36m",
    Verdict.SUSPICIOUS: "\x1b[33m",
    Verdict.LIKELY: "\x1b[31m",
    Verdict.HIGH: "\x1b[1;31m",
}
_TIER_MARK = {Tier.STRONG: "!!!", Tier.SUSPICIOUS: " ! ", Tier.CONTEXT: " . "}
_RESET = "\x1b[0m"


def _clean(value: str) -> str:
    return neutralize(value)


def _public_metadata(report: TriageReport) -> Dict[str, str]:
    return {key: value for key, value in report.parsed.metadata.items() if not key.startswith("_")}


def console(reports: Sequence[TriageReport], color: bool = False, verbose: bool = False) -> str:
    lines: List[str] = []
    for report in reports:
        lines.extend(_console_one(report, color, verbose))
        lines.append("")
    if len(reports) > 1:
        counts: Dict[Verdict, int] = {}
        for report in reports:
            counts[report.verdict] = counts.get(report.verdict, 0) + 1
        summary = ", ".join("%d %s" % (counts[v], v.label) for v in sorted(counts, reverse=True))
        lines.append("Tổng cộng %d tệp: %s" % (len(reports), summary))
    lines.append(
        "Đây là phân tích TĨNH ở bản beta: gợi ý để người phòng thủ quyết định, không phải phán quyết tuyệt đối."
    )
    return "\n".join(lines) + "\n"


def _console_one(report: TriageReport, color: bool, verbose: bool) -> List[str]:
    parsed = report.parsed
    tint = _COLORS[report.verdict] if color else ""
    reset = _RESET if color else ""
    lines = [
        display_path(report.path),
        "  %s[%s] %s%s  ( điểm %d/100 )" % (tint, _ICONS[report.verdict], report.verdict.label, reset, report.score),
        "  định dạng: %s%s%s" % (
            _clean(parsed.format),
            ( ", " + _clean(parsed.arch) ) if parsed.arch else "",
            _traits(parsed.traits),
        ),
        "  kích thước: %d byte   sha256: %s" % (report.size, report.hashes["sha256"]),
    ]
    if parsed.signature.present:
        hint = ( " - " + ", ".join(_clean(h) for h in parsed.signature.signer_hints[:3]) ) if parsed.signature.signer_hints else ""
        lines.append("  chữ ký: có ( %s, CHƯA kiểm tính hợp lệ )%s" % (_clean(parsed.signature.kind), hint))
    elif parsed.family in ("pe", "macho", "jar"):
        lines.append("  chữ ký: không có")
    lines.append("  độ tin cậy: %s" % report.confidence)
    if report.reasons:
        lines.append("  vì sao:")
        lines.extend("    - %s" % reason for reason in report.reasons)
    if report.hits:
        lines.append("  dấu hiệu:")
    for hit in report.hits:
        if hit.tier is Tier.CONTEXT and not verbose:
            continue
        lines.extend(_console_hit(hit, verbose))
    hidden = sum(1 for hit in report.hits if hit.tier is Tier.CONTEXT)
    if hidden and not verbose:
        lines.append("    ( %d dấu hiệu bối cảnh được ẩn; thêm -v để xem )" % hidden)
    if report.iocs:
        lines.append("  IOC:")
        for ioc in report.iocs[: 40 if verbose else 10]:
            lines.append("    %s: %s" % (ioc.kind, _clean(ioc.value)))
    for note in report.notes:
        lines.append("  ghi chú: %s" % _clean(note))
    if verbose:
        lines.append("  giới hạn:")
        lines.extend("    - %s" % item for item in report.limitations)
    lines.append("  nên làm:")
    for step in report.guidance[: None if verbose else 3]:
        lines.append("    - %s" % step)
    return lines


def _traits(traits: List[str]) -> str:
    shown = [_clean(t) for t in traits if not t.startswith("wx-segment")]
    return " [%s]" % ", ".join(shown) if shown else ""


def _console_hit(hit: IndicatorHit, verbose: bool) -> List[str]:
    spec = hit.spec
    lines = [
        "   %s %s  %s  [%s]%s" % (
            _TIER_MARK[hit.tier],
            spec.id,
            spec.title,
            hit.tier.label,
            ( "  ATT&CK " + ", ".join(spec.attack) ) if spec.attack else "",
        )
    ]
    for item in hit.evidence[: None if verbose else 3]:
        where = ( "  @ " + _clean(item.location) ) if item.location else ""
        lines.append("         %s%s" % (_clean(item.detail)[:200], where))
    if verbose:
        lines.append("         lành tính có thể: %s" % spec.benign)
        lines.append("         khắc phục: %s" % spec.remediation)
    return lines


def _report_dict(report: TriageReport) -> Dict[str, Any]:
    parsed = report.parsed
    return {
        "path": report.path,
        "size": report.size,
        "truncated": report.truncated,
        "hashes": report.hashes,
        "verdict": report.verdict.key,
        "verdict_label": report.verdict.label,
        "score": report.score,
        "confidence": report.confidence,
        "reasons": report.reasons,
        "format": {
            "name": parsed.format,
            "family": parsed.family,
            "arch": parsed.arch,
            "traits": parsed.traits,
            "packers": parsed.packers,
            "metadata": _public_metadata(report),
            "timestamp": parsed.timestamp,
            "entry_point": parsed.entry_point,
            "entry_section": parsed.entry_section,
            "signature": {
                "present": parsed.signature.present,
                "kind": parsed.signature.kind,
                "signer_hints": parsed.signature.signer_hints,
                "verified": False,
            },
            "sections": [
                {
                    "name": s.name,
                    "offset": s.offset,
                    "raw_size": s.raw_size,
                    "virtual_size": s.virtual_size,
                    "entropy": round(s.entropy, 3),
                    "writable": s.writable,
                    "executable": s.executable,
                }
                for s in parsed.sections[:256]
            ],
            "libraries": parsed.libraries[:512],
            "import_count": len(parsed.imports),
            "export_count": len(parsed.exports),
            "resources": [
                {"type": r.type, "name": r.name, "size": r.size, "entropy": round(r.entropy, 3), "offset": r.offset}
                for r in parsed.resources[:256]
            ],
            "overlay": (
                {
                    "offset": parsed.overlay.offset,
                    "size": parsed.overlay.size,
                    "entropy": round(parsed.overlay.entropy, 3),
                    "kind": parsed.overlay.kind,
                }
                if parsed.overlay
                else None
            ),
            "anomalies": parsed.anomalies,
        },
        "indicators": [
            {
                "id": hit.spec.id,
                "category": hit.spec.category,
                "tier": hit.tier.key,
                "weight": hit.spec.weight,
                "title": hit.spec.title,
                "attack": list(hit.spec.attack),
                "evidence": [{"detail": e.detail, "location": e.location} for e in hit.evidence],
                "rationale": hit.spec.rationale,
                "benign_explanations": hit.spec.benign,
                "remediation": hit.spec.remediation,
            }
            for hit in report.hits
        ],
        "iocs": [{"kind": i.kind, "value": i.value, "location": i.location} for i in report.iocs],
        "notes": report.notes,
        "limitations": report.limitations,
        "guidance": report.guidance,
    }


def to_json(reports: Sequence[TriageReport], version: str) -> str:
    payload = {
        "tool": "fortress-scan binary",
        "version": version,
        "schema": SCHEMA_VERSION,
        "beta": True,
        "files": [_report_dict(report) for report in reports],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def _md(value: str) -> str:
    return _clean(value).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def to_markdown(reports: Sequence[TriageReport], version: str) -> str:
    lines = [
        "# Báo cáo phân tích file thực thi ( beta )",
        "",
        "Công cụ: fortress-scan binary %s. Phân tích tĩnh, không chạy tệp." % version,
        "",
        "| Tệp | Kết luận | Điểm | Định dạng | SHA-256 |",
        "| :--- | :--- | ---: | :--- | :--- |",
    ]
    for report in reports:
        lines.append(
            "| `%s` | %s | %d | %s | `%s` |"
            % (_md(display_path(report.path)), report.verdict.label, report.score, _md(report.parsed.format), report.hashes["sha256"])
        )
    for report in reports:
        lines += ["", "## `%s`" % _md(display_path(report.path)), "", "**Kết luận:** %s ( %d/100 )" % (report.verdict.label, report.score), ""]
        lines.append("**Độ tin cậy:** %s" % _md(report.confidence))
        if report.hits:
            lines += ["", "| Mã | Dấu hiệu | Bậc | ATT&CK | Bằng chứng |", "| :--- | :--- | :--- | :--- | :--- |"]
            for hit in report.hits:
                proof = "<br>".join(_md(e.detail[:160]) + ( " @ " + _md(e.location) if e.location else "" ) for e in hit.evidence[:4])
                lines.append("| %s | %s | %s | %s | %s |" % (hit.spec.id, _md(hit.spec.title), hit.tier.label, ", ".join(hit.spec.attack), proof))
        if report.iocs:
            lines += ["", "**IOC**", ""]
            lines += ["- %s: `%s`" % (i.kind, _md(i.value)) for i in report.iocs[:50]]
        lines += ["", "**Nên làm**", ""] + ["1. %s" % step for step in report.guidance]
        remediations = []
        for hit in report.hits:
            if hit.tier >= Tier.SUSPICIOUS and hit.spec.remediation not in remediations:
                remediations.append(hit.spec.remediation)
        if remediations:
            lines += ["", "**Khắc phục theo từng dấu hiệu**", ""] + ["- %s" % _md(item) for item in remediations]
        lines += ["", "**Giới hạn**", ""] + ["- %s" % _md(item) for item in report.limitations + report.notes]
    return "\n".join(lines) + "\n"
