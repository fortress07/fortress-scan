from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

from .strings import StringPool


class Tier(IntEnum):
    """Sức nặng của MỘT dấu hiệu khi đứng một mình."""

    CONTEXT = 1  # phổ biến cả ở phần mềm lành, chỉ để bối cảnh
    SUSPICIOUS = 2  # đáng ngờ, có giải thích lành tính nhưng hiếm
    STRONG = 3  # gần như chỉ thấy ở ransomware hoặc công cụ phá hoại

    @property
    def label(self) -> str:
        return {1: "bối cảnh", 2: "đáng ngờ", 3: "mạnh"}[int(self)]

    @property
    def key(self) -> str:
        return {1: "context", 2: "suspicious", 3: "strong"}[int(self)]


class Verdict(IntEnum):
    NONE = 0
    LOW = 1
    SUSPICIOUS = 2
    LIKELY = 3
    HIGH = 4

    @property
    def key(self) -> str:
        return ("none", "low", "suspicious", "likely", "high")[int(self)]

    @property
    def label(self) -> str:
        return (
            "không thấy dấu hiệu ransomware",
            "cần lưu ý ( chỉ có dấu hiệu bối cảnh )",
            "đáng ngờ",
            "nhiều khả năng là ransomware",
            "dấu hiệu ransomware rõ rệt",
        )[int(self)]


@dataclass(frozen=True)
class Evidence:
    detail: str
    location: str = ""


@dataclass(frozen=True)
class IndicatorSpec:
    id: str
    category: str  # structural | capability | content
    tier: Tier
    weight: int
    title: str
    rationale: str
    benign: str
    remediation: str
    attack: Tuple[str, ...] = ()


@dataclass
class IndicatorHit:
    spec: IndicatorSpec
    evidence: List[Evidence] = field(default_factory=list)
    # Detector được phép nâng/hạ bậc theo bằng chứng cụ thể ( ví dụ ghi chú
    # tống tiền đủ 5 nhóm cụm từ thì chắc hơn chỉ đủ 3 ).
    tier_override: Optional[Tier] = None

    @property
    def tier(self) -> Tier:
        return self.tier_override if self.tier_override is not None else self.spec.tier


@dataclass(frozen=True)
class Section:
    name: str
    offset: int
    raw_size: int
    virtual_size: int
    entropy: float
    readable: bool = True
    writable: bool = False
    executable: bool = False
    virtual_address: int = 0


@dataclass(frozen=True)
class Import:
    library: str
    name: str
    ordinal: Optional[int] = None
    delayed: bool = False


@dataclass(frozen=True)
class Resource:
    type: str
    name: str
    size: int
    entropy: float
    offset: int


@dataclass(frozen=True)
class Overlay:
    offset: int
    size: int
    entropy: float
    kind: str = ""


@dataclass
class Signature:
    present: bool = False
    kind: str = ""
    signer_hints: List[str] = field(default_factory=list)


@dataclass
class Parsed:
    """Kết quả phân tích cấu trúc, chung cho mọi định dạng."""

    format: str
    family: str  # pe | elf | macho | jar | zip | script | unknown
    arch: str = ""
    traits: List[str] = field(default_factory=list)  # dll, .net, go, pyinstaller, ...
    sections: List[Section] = field(default_factory=list)
    imports: List[Import] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    names: List[Tuple[str, str]] = field(default_factory=list)  # (định danh, nguồn)
    resources: List[Resource] = field(default_factory=list)
    overlay: Optional[Overlay] = None
    timestamp: Optional[int] = None
    signature: Signature = field(default_factory=Signature)
    entry_point: Optional[int] = None
    entry_section: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)
    anomalies: List[str] = field(default_factory=list)
    embedded: List[Tuple[str, bytes]] = field(default_factory=list)
    embedded_text: List[Tuple[str, str]] = field(default_factory=list)
    packers: List[str] = field(default_factory=list)
    children: List["Parsed"] = field(default_factory=list)
    imphash: str = ""

    def has_trait(self, trait: str) -> bool:
        return trait in self.traits


@dataclass
class Ioc:
    kind: str
    value: str
    location: str = ""


@dataclass
class TriageReport:
    path: str
    size: int
    hashes: Dict[str, str]
    parsed: Parsed
    hits: List[IndicatorHit]
    verdict: Verdict
    score: int
    confidence: str
    reasons: List[str]
    limitations: List[str]
    iocs: List[Ioc]
    guidance: List[str]
    truncated: bool = False
    notes: List[str] = field(default_factory=list)
    pool: Optional[StringPool] = None

    @property
    def strong_hits(self) -> List[IndicatorHit]:
        return [hit for hit in self.hits if hit.tier is Tier.STRONG]
