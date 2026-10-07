from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional, Tuple


class Severity(IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @property
    def label(self) -> str:
        return self.name.lower()


class Confidence(IntEnum):
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CERTAIN = 40

    @property
    def label(self) -> str:
        return self.name.lower()


class Category(str, Enum):
    CODE_EXECUTION = "code-execution"
    COMMAND = "os-command"
    SQL = "sql"
    NOSQL = "nosql"
    LDAP = "ldap"
    XPATH = "xpath"
    TEMPLATE = "template"
    DESERIALIZATION = "deserialization"
    DYNAMIC_IMPORT = "dynamic-import"
    REFLECTION = "reflection"
    EXPRESSION_LANGUAGE = "expression-language"
    MARKUP = "markup"
    XML = "xml"
    UNICODE = "unicode"
    SUPPLY_CHAIN = "supply-chain"
    PATH = "path"
    SSRF = "ssrf"
    REDIRECT = "redirect"
    HTTP_HEADER = "http-header"
    CRYPTO = "crypto"
    TLS = "tls"
    SECRET = "hardcoded-secret"
    JWT = "jwt"
    CORS = "cors"
    COOKIE = "cookie"
    ACCESS_CONTROL = "access-control"
    MASS_ASSIGNMENT = "mass-assignment"
    PERMISSION = "file-permission"
    TEMP_FILE = "temp-file"
    DEBUG = "debug"
    PROTOTYPE = "prototype-pollution"


class StepKind(str, Enum):
    SOURCE = "source"
    PROPAGATION = "propagation"
    SANITIZER = "sanitizer"
    CALL = "call"
    SINK = "sink"


class PathContext(str, Enum):
    """Vai trò của tệp trong dự án, suy từ đường dẫn.

    Một lời gọi ``eval`` trong ``tests/fixtures/`` và một lời gọi ``eval`` trong
    ``app/views.py`` là hai sự việc khác hẳn nhau về mức độ khẩn, dù cùng một
    hình dạng mã. Bộ dò không có quyền GIẤU cái thứ nhất -- nó vẫn có thể là lỗ
    hổng thật -- nhưng báo cả hai ở cùng một độ tin cậy thì người đọc mất luôn
    thước đo. Ngữ cảnh đi kèm phát hiện để họ tự cân, và để --min-confidence
    lọc được theo đúng cái họ muốn.
    """

    PRODUCTION = "production"
    TEST = "test"
    EXAMPLE = "example"
    GENERATED = "generated"
    VENDORED = "vendored"
    DOCUMENTATION = "documentation"

    @property
    def is_production(self) -> bool:
        return self is PathContext.PRODUCTION


_SEVERITY_BY_NAME = {item.name.lower(): item for item in Severity}
_CONFIDENCE_BY_NAME = {item.name.lower(): item for item in Confidence}


def parse_severity(value: str) -> Severity:
    key = str(value).strip().lower()
    if key not in _SEVERITY_BY_NAME:
        raise ValueError(
            "mức độ %r không hợp lệ (phải là một trong: %s)"
            % (value, ", ".join(sorted(_SEVERITY_BY_NAME)))
        )
    return _SEVERITY_BY_NAME[key]


def parse_confidence(value: str) -> Confidence:
    key = str(value).strip().lower()
    if key not in _CONFIDENCE_BY_NAME:
        raise ValueError(
            "độ tin cậy %r không hợp lệ (phải là một trong: %s)"
            % (value, ", ".join(sorted(_CONFIDENCE_BY_NAME)))
        )
    return _CONFIDENCE_BY_NAME[key]


@dataclass(frozen=True)
class TraceStep:
    kind: StepKind
    line: int
    column: int
    label: str
    code: str = ""
    # Bước nằm ở tệp khác với tệp của phát hiện ( đường đi xuyên file );
    # rỗng nghĩa là cùng tệp.
    path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "kind": self.kind.value,
            "line": self.line,
            "column": self.column,
            "label": self.label,
            "code": self.code,
        }
        if self.path:
            result["path"] = self.path
        return result


_WHITESPACE = re.compile(r"\s+")


def _normalize(text: str) -> str:
    return _WHITESPACE.sub(" ", text).strip()


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    category: Category
    path: str
    line: int
    column: int
    end_line: int
    end_column: int
    language: str
    snippet: str = ""
    symbol: str = ""
    cwe: Tuple[str, ...] = ()
    owasp: Tuple[str, ...] = ()
    remediation: str = ""
    references: Tuple[str, ...] = ()
    trace: Tuple[TraceStep, ...] = ()
    tags: Tuple[str, ...] = ()
    # Vì sao bộ dò tin ( hoặc bớt tin ) vào phát hiện này. Mỗi mục là một câu
    # kiểm chứng được bằng mắt trên chính đoạn mã, không phải lời quảng cáo:
    # nguồn nào, đi qua gì, cái gì đã nâng hay hạ độ tin cậy. Người đọc cần
    # bác bỏ được một phát hiện sai nhanh bằng đúng thứ đã tạo ra nó.
    evidence: Tuple[str, ...] = ()
    # Vai trò của tệp chứa phát hiện. Không lọc bỏ gì, chỉ nói ra.
    context: PathContext = PathContext.PRODUCTION
    # Thứ tự trong nhóm những phát hiện giống hệt nhau ở cùng một tệp; xem
    # `fingerprint`.
    occurrence: int = 0

    @property
    def fingerprint_material(self) -> str:
        return "\x1f".join(
            (
                self.rule_id,
                self.path.replace("\\", "/"),
                self.symbol,
                _normalize(self.snippet),
            )
        )

    @property
    def fingerprint(self) -> str:
        """Danh tính bền của một phát hiện, dùng cho baseline và SARIF.

        Cố ý không chứa số dòng: thêm một dòng import ở đầu tệp thì mọi phát
        hiện phía dưới không được biến thành phát hiện mới.

        Nhưng chỉ chừng đó thì hai dòng thủng giống hệt nhau trong cùng một
        tệp cho ra cùng một vân tay, và hậu quả rất nặng: baseline ghi lúc mới
        có một dòng sẽ che luôn dòng thứ hai thêm vào sau. Người ta thêm một
        lỗ hổng, còn công cụ báo sạch. Số thứ tự tách chúng ra.

        Phát hiện đầu tiên trong nhóm giữ nguyên vân tay cũ, vì số thứ tự 0
        không đi vào phép băm. Nhờ vậy mọi baseline đã ghi vẫn dùng được.
        """
        material = self.fingerprint_material
        if self.occurrence:
            material = "%s\x1f#%d" % (material, self.occurrence)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]

    @property
    def sort_key(self) -> Tuple[Any, ...]:
        return (
            -int(self.severity),
            -int(self.confidence),
            self.path.replace("\\", "/"),
            self.line,
            self.column,
            self.rule_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity.label,
            "confidence": self.confidence.label,
            "category": self.category.value,
            "path": self.path.replace("\\", "/"),
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "language": self.language,
            "snippet": self.snippet,
            "symbol": self.symbol,
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "remediation": self.remediation,
            "references": list(self.references),
            "trace": [step.to_dict() for step in self.trace],
            "tags": list(self.tags),
            "evidence": list(self.evidence),
            "context": self.context.value,
            "fingerprint": self.fingerprint,
        }


@dataclass
class ScanError:
    path: str
    reason: str
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.path.replace("\\", "/"), "reason": self.reason, "detail": self.detail}


@dataclass
class ScanNotice:
    """Một thứ đã làm hẹp phạm vi quét so với mặc định.

    Khác `ScanError` ở chỗ không có gì hỏng cả: lượt quét chạy đúng như được
    yêu cầu, chỉ là nó đã nhìn ít hơn -- vì tệp cấu hình trong cây được quét,
    vì liên kết bị bỏ qua, vì ngưỡng bị nâng lên. Một báo cáo "sạch" sinh ra
    từ những thứ đó phải nói được vì sao nó sạch, và phải nói ở MỌI định dạng
    chứ không riêng màn hình -- người đọc JSON hay SARIF cũng cần biết.
    """

    kind: str
    summary: str
    details: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "summary": self.summary, "details": list(self.details)}


@dataclass
class ScanStats:
    files_discovered: int = 0
    files_analyzed: int = 0
    files_skipped: int = 0
    directories_excluded: int = 0
    bytes_analyzed: int = 0
    duration_seconds: float = 0.0
    languages: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "files_discovered": self.files_discovered,
            "files_analyzed": self.files_analyzed,
            "files_skipped": self.files_skipped,
            "directories_excluded": self.directories_excluded,
            "bytes_analyzed": self.bytes_analyzed,
            "duration_seconds": round(self.duration_seconds, 4),
            "languages": dict(sorted(self.languages.items())),
        }


@dataclass
class ScanResult:
    root: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[ScanError] = field(default_factory=list)
    notices: List[ScanNotice] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    suppressed: int = 0
    baselined: int = 0
    # Phát hiện thật, đã dựng xong, nhưng nằm ngoài phạm vi --diff. Đếm riêng
    # với baseline: baseline là "đã biết và chấp nhận", còn cái này là "chưa
    # xét vì lần chạy này chỉ soi phần vừa đổi". Trộn hai con số lại là nói
    # dối người đọc về thứ họ vừa được miễn.
    out_of_diff: int = 0

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {item.label: 0 for item in Severity}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(finding.severity for finding in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root.replace("\\", "/"),
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": [error.to_dict() for error in self.errors],
            "notices": [notice.to_dict() for notice in self.notices],
            "stats": self.stats.to_dict(),
            "summary": {
                "total": len(self.findings),
                "by_severity": self.counts_by_severity(),
                "suppressed": self.suppressed,
                "baselined": self.baselined,
                "out_of_diff": self.out_of_diff,
            },
        }
