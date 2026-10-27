from __future__ import annotations

import json
from typing import Any, Dict, List

from ..core.model import Finding, ScanResult, Severity
from ..core.registry import all_rules, get_rule, rules_digest
from ..security.text import display_path, neutralize

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_json(result: ScanResult, tool_version: str) -> str:
    payload = result.to_dict()
    payload["tool"] = {
        "name": "fortress-scan",
        "version": tool_version,
        "rules_digest": rules_digest(),
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


def to_sarif(result: ScanResult, tool_version: str) -> str:
    used_rules = sorted({finding.rule_id for finding in result.findings})
    rules: List[Dict[str, Any]] = []
    for rule_id in used_rules:
        rule = get_rule(rule_id)
        rules.append(
            {
                "id": rule.id,
                "name": rule.id.replace("-", ""),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.remediation},
                "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
                "properties": {
                    "tags": ["security", rule.category.value] + list(rule.cwe) + list(rule.owasp),
                    "problem.severity": rule.severity.label,
                    "security-severity": _security_severity(rule.severity),
                },
            }
        )

    results: List[Dict[str, Any]] = []
    for finding in result.findings:
        start_column = max(1, finding.column + 1)
        # SARIF endColumn là loại trừ; điểm cuối 0-based của AST cũng loại
        # trừ nên chỉ cần dịch 1. Kết quả token-based có thể ra vùng rộng 0
        # nên chặn trên startColumn + 1 để không sinh vùng rỗng.
        end_column = max(start_column + 1, finding.end_column + 1)
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {"text": finding.message},
                "fingerprints": {"fortress-scan/v1": finding.fingerprint},
                "partialFingerprints": {"fortress-scan/v1": finding.fingerprint},
                "properties": {
                    "confidence": finding.confidence.label,
                    "category": finding.category.value,
                    # Bằng chứng và ngữ cảnh đi kèm vào SARIF chứ không dừng ở
                    # màn hình: code scanning của CI đọc tệp này, và người bấm
                    # vào một cảnh báo ở đó cần đúng những dòng lý do như
                    # người chạy trên terminal.
                    "context": finding.context.value,
                    "evidence": list(finding.evidence),
                    "tags": list(finding.tags),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": display_path(finding.path),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding.line,
                                "startColumn": start_column,
                                "endLine": max(finding.line, finding.end_line),
                                "endColumn": end_column,
                                "snippet": {"text": finding.snippet},
                            },
                        }
                    }
                ],
                "codeFlows": _code_flows(finding),
            }
        )

    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Fortress Scan",
                        "version": tool_version,
                        "informationUri": (
                            "https://github.com/fortress07/fortress-scan"
                        ),
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": _root_uri(result.root)}
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": _notifications(result),
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def _notifications(result: ScanResult) -> List[Dict[str, Any]]:
    """Mọi thứ làm hẹp phạm vi quét, đặt vào đúng chỗ của SARIF.

    Không có phần này thì một lượt quét bị tệp cấu hình trong cây mục tiêu bóp
    còn một nửa vẫn xuất ra tệp SARIF trông y hệt một lượt quét sạch thật sự.
    """
    notifications: List[Dict[str, Any]] = []
    # Chú thích `fortress-scan: ignore` nằm trong chính mã được quét, nên nó là
    # thứ người viết repo điều khiển được -- đúng loại dữ liệu không tin cậy như
    # .fortress-scan.json ở trên. Console có đếm và nói ra, SARIF thì không, mà
    # SARIF mới là đường đi vào code scanning của CI: một phát hiện critical bị
    # một dòng chú thích che đi từng xuất ra tệp SARIF rỗng hoàn toàn, không một
    # dấu vết nào cho người đọc biết là đã có thứ bị gỡ.
    if result.suppressed or result.baselined:
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": (
                        "%d phát hiện bị ẩn bởi chú thích fortress-scan: ignore trong mã "
                        "được quét, %d bị ẩn bởi baseline; chạy lại với "
                        "--no-inline-suppressions và bỏ --baseline để thấy đầy đủ"
                        % (result.suppressed, result.baselined)
                    )
                },
                "descriptor": {"id": "findings-suppressed"},
            }
        )
    for notice in result.notices:
        text = "\n".join((notice.summary,) + tuple(notice.details))
        notifications.append(
            {
                "level": "warning",
                "message": {"text": text},
                "descriptor": {"id": notice.kind},
            }
        )
    for error in result.errors:
        detail = " ".join(part for part in (error.reason, error.detail) if part)
        notifications.append(
            {
                "level": "warning",
                "message": {"text": "%s: %s" % (display_path(error.path), detail)},
                "descriptor": {"id": error.reason},
            }
        )
    return notifications


def _code_flows(finding: Finding) -> List[Dict[str, Any]]:
    if not finding.trace:
        return []
    locations = []
    for step in finding.trace:
        # Bước xuyên file mang tệp của riêng nó; bước thường thì thuộc về tệp
        # của phát hiện.
        step_uri = display_path(step.path) if step.path else display_path(finding.path)
        locations.append(
            {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": step_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(1, step.line),
                            "startColumn": max(1, step.column + 1),
                        },
                    },
                    "message": {"text": step.label},
                }
            }
        )
    return [{"threadFlows": [{"locations": locations}]}]


def _security_severity(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "9.3",
        Severity.HIGH: "7.5",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.1",
        Severity.INFO: "1.0",
    }[severity]


def _root_uri(root: str) -> str:
    normalized = root.replace("\\", "/")
    if not normalized.endswith("/"):
        normalized += "/"
    if len(normalized) > 2 and normalized[1] == ":":
        return "file:///" + normalized
    return "file://" + normalized


def to_markdown(result: ScanResult, tool_version: str) -> str:
    lines: List[str] = []
    counts = result.counts_by_severity()
    lines.append("# Báo cáo Fortress Scan")
    lines.append("")
    lines.append(
        "Đã quét %s bằng Fortress Scan %s."
        % (_inline_code(display_path(result.root)), tool_version)
    )
    lines.append("")
    lines.append("| Mức độ | Số lượng |")
    lines.append("| --- | --- |")
    for severity in sorted(Severity, reverse=True):
        lines.append("| %s | %d |" % (severity.label, counts.get(severity.label, 0)))
    lines.append("")
    lines.append(
        "Đã phân tích %d tệp trong %.2f giây."
        % (result.stats.files_analyzed, result.stats.duration_seconds)
    )
    if result.stats.files_skipped:
        lines.append("")
        lines.append("Bỏ qua %d tệp, không được phân tích." % result.stats.files_skipped)
    # Cùng lý do với thông báo `findings-suppressed` của SARIF: console có đếm số
    # phát hiện bị chú thích trong mã che đi, còn bản Markdown thì từng im lặng --
    # và Markdown mới là bản người ta dán vào ticket hay gửi cho nhau đọc.
    if result.suppressed or result.baselined:
        lines.append("")
        lines.append(
            "**%d phát hiện bị ẩn** bởi chú thích `fortress-scan: ignore` trong mã được "
            "quét, %d bị ẩn bởi baseline. Chạy lại với `--no-inline-suppressions` và bỏ "
            "`--baseline` để thấy đầy đủ." % (result.suppressed, result.baselined)
        )
    lines.append("")

    # Đặt trước phần phát hiện, và trước cả nhánh "không có phát hiện nào":
    # đây chính là lúc người đọc cần biết vì sao báo cáo lại sạch.
    if result.notices:
        lines.append("## ⚠️ Phạm vi quét đã bị thu hẹp")
        lines.append("")
        for notice in result.notices:
            lines.append("- %s" % _escape(notice.summary))
            for detail in notice.details:
                lines.append("  - %s" % _escape(detail))
        lines.append("")

    if not result.findings:
        lines.append("Không phát hiện lỗ hổng code injection nào.")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Các phát hiện")
    lines.append("")
    for finding in result.findings:
        rule = get_rule(finding.rule_id)
        lines.append(
            "### %s - %s" % (finding.rule_id, _escape(finding.title))
        )
        lines.append("")
        lines.append(
            "- Vị trí: %s"
            % _inline_code(
                "%s:%d:%d" % (display_path(finding.path), finding.line, finding.column)
            )
        )
        lines.append(
            "- Mức độ: **%s** | Độ tin cậy: %s | Nhóm: %s"
            % (finding.severity.label, finding.confidence.label, finding.category.value)
        )
        if not finding.context.is_production:
            lines.append("- Ngữ cảnh tệp: %s" % _escape(finding.context.value))
        if finding.cwe:
            lines.append("- Điểm yếu: %s" % ", ".join(finding.cwe))
        if finding.owasp:
            lines.append("- OWASP: %s" % ", ".join(finding.owasp))
        lines.append("- Vân tay: `%s`" % finding.fingerprint)
        lines.append("")
        lines.append(_escape(finding.message))
        lines.append("")
        if finding.snippet:
            fence = _fence(finding.snippet)
            lines.append(fence)
            lines.append(finding.snippet)
            lines.append(fence)
            lines.append("")
        if finding.trace:
            lines.append("Đường đi của dữ liệu:")
            lines.append("")
            for step in finding.trace:
                where = "dòng %d" % step.line
                if step.path:
                    where += " trong %s" % _inline_code(_escape(display_path(step.path)))
                lines.append(
                    "1. %s - %s (%s)"
                    % (where, _escape(step.label), _inline_code(neutralize(step.code)))
                )
            lines.append("")
        if finding.evidence:
            # Cùng nội dung với phần "căn cứ" của báo cáo console. Markdown là
            # định dạng hay được dán vào pull request, tức là chỗ mà người
            # phản biện quyết định tin hay bác bỏ -- giấu phần lý do ở đây thì
            # họ phải chạy lại công cụ mới thấy được thứ đã có sẵn.
            lines.append("Căn cứ:")
            lines.append("")
            for reason in finding.evidence:
                lines.append("- %s" % _escape(reason))
            lines.append("")
        lines.append("**Cách khắc phục.** %s" % _escape(rule.remediation))
        lines.append("")
    return "\n".join(lines)


def rules_catalogue() -> str:
    lines = ["# Danh mục rule của Fortress Scan", ""]
    lines.append("| Mã | Mức độ | Nhóm | Tên |")
    lines.append("| --- | --- | --- | --- |")
    for rule in all_rules():
        lines.append(
            "| %s | %s | %s | %s |"
            % (rule.id, rule.severity.label, rule.category.value, _escape(rule.title))
        )
    lines.append("")
    return "\n".join(lines)


def rule_explanation(rule_id: str) -> str:
    """Toàn bộ những gì công cụ biết về một rule, dạng đọc được trên terminal.

    `--list-rules` trả lời "có những rule nào"; câu hỏi thật sự của người vừa
    nhận một phát hiện lại là "vì sao đây là lỗ hổng, và sửa thế nào cho đúng".
    Trước đây họ phải mở README hoặc đọc mã nguồn registry để biết -- mà phần
    khắc phục thì công cụ đã có sẵn trong tay ngay từ đầu.
    """
    rule = get_rule(rule_id)
    lines = [
        "%s  %s" % (rule.id, rule.title),
        "",
        "Mức độ      : %s" % rule.severity.label,
        "Độ tin cậy  : %s (mặc định của rule)" % rule.confidence.label,
        "Nhóm        : %s" % rule.category.value,
    ]
    if rule.cwe:
        lines.append("CWE         : %s" % ", ".join(rule.cwe))
    if rule.owasp:
        lines.append("OWASP       : %s" % ", ".join(rule.owasp))
    lines.extend(["", "Vì sao đây là vấn đề", "-" * 20, rule.description])
    if rule.remediation:
        lines.extend(["", "Cách khắc phục", "-" * 20, rule.remediation])
    if rule.references:
        lines.extend(["", "Đọc thêm", "-" * 20])
        lines.extend("  %s" % item for item in rule.references)
    lines.extend(
        [
            "",
            "Tắt riêng rule này : fortress-scan --disable %s" % rule.id,
            "Chỉ chạy rule này  : fortress-scan --enable %s" % rule.id,
        ]
    )
    # neutralize() TỪNG DÒNG rồi mới nối lại: nội dung rule do chính dự án
    # viết, nhưng đường ra thì dùng chung với mọi thứ khác và một chỗ duy nhất
    # chịu trách nhiệm thì không ai phải nhớ. Neutralize cả khối một lượt thì
    # chính dấu xuống dòng cũng bị escape, và tài liệu nhiều đoạn biến thành
    # một dòng dài đặc \\x0a.
    return "\n".join(neutralize(line) for line in lines) + "\n"


def _escape(text: str) -> str:
    # neutralize() chạy trước cả escape cú pháp. Escape sequence của terminal đi
    # xuyên qua `|` `<` `>` nguyên vẹn rồi nổ ra khi ai đó cat tệp .md; JSON và
    # SARIF thoát nạn nhờ json.dumps, Markdown thì không có ai lo hộ.
    #
    # Backtick và ngoặc vuông đi kèm vì chúng cũng là cú pháp: một backtick lẻ
    # mở ra vùng mã và nuốt phần sau, còn `[chữ](http://...)` là một liên kết
    # thật mà người đọc tưởng do công cụ viết ra.
    escaped = neutralize(text).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")
    return escaped.replace("`", "\\`").replace("[", "\\[").replace("]", "\\]")


def _longest_backtick_run(text: str) -> int:
    longest = 0
    current = 0
    for char in text:
        if char == "`":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _fence(text: str) -> str:
    """Hàng rào dài hơn mọi chuỗi dấu ` có trong nội dung.

    Hàng rào cứng ba dấu là một lỗ hổng: trích đoạn mã là do người viết tệp
    được quét soạn ra, nên chỉ cần đặt ``` vào giữa dòng là khối mã đóng sớm và
    phần đuôi rơi ra ngoài thành Markdown thật -- đủ để nhét HTML, liên kết,
    hay nguyên một mục "Các phát hiện" giả vào bản báo cáo mà người ta đang đọc
    để ra quyết định.
    """
    return "`" * max(3, _longest_backtick_run(text) + 1)


def _inline_code(text: str) -> str:
    """Vùng mã nội dòng cho một chuỗi đến từ tệp được quét.

    Cùng lý do với _fence, chỉ khác là CommonMark còn đòi thêm một khoảng trắng
    đệm khi nội dung bắt đầu hoặc kết thúc bằng dấu `.
    """
    ticks = "`" * (_longest_backtick_run(text) + 1)
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return "%s%s%s%s%s" % (ticks, padding, text, padding, ticks)
