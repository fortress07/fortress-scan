from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Dict, FrozenSet, Iterable, Optional, Tuple

from ...core.model import Category, Confidence, TraceStep

MAX_TRACE_STEPS = 12
MAX_TEXT_PARTS = 24
MAX_CALLABLE_REFS = 8
MAX_ENTRIES = 32

# Chặn trên cho phần văn bản giữ lại của MỘT hằng chuỗi. Con số này phải đủ
# rộng cho những phép nhận dạng chạy trên `Value.text` - đáng kể nhất là
# looks_like_sql(), vốn cần nhìn thấy `from` đứng sau `select`. Ở mức 512 cũ
# hai hạn mức đá nhau âm thầm: một câu SELECT liệt kê 40 cột dài hơn 800 ký
# tự bị cắt mất `from`, nên sink SQL với receiver lạ không còn được nhận ra
# dù cửa sổ của chính looks_like_sql() rộng hơn nhiều.
MAX_LITERAL_TEXT = 4096


@dataclass(frozen=True)
class CallableRef:
    """Which function a value refers to.

    Sink matching is name based, so a callable that is stored in a variable, put
    in a container or produced by ``getattr`` would otherwise lose the name it
    is matched by. This travels with the value and keeps it recognisable.
    """

    qualname: str
    attribute: Optional[str] = None
    receiver: Optional[str] = None

    def sort_key(self) -> Tuple[str, str, str]:
        return (self.qualname, self.attribute or "", self.receiver or "")


def limit_callables(refs: FrozenSet[CallableRef]) -> FrozenSet[CallableRef]:
    if len(refs) <= MAX_CALLABLE_REFS:
        return refs
    return frozenset(sorted(refs, key=CallableRef.sort_key)[:MAX_CALLABLE_REFS])


def merge_callables(
    left: FrozenSet[CallableRef], right: FrozenSet[CallableRef]
) -> FrozenSet[CallableRef]:
    if not left:
        return right
    if not right:
        return left
    return limit_callables(left | right)


def maps_its_callables(value: "Value") -> bool:
    """Whether a key map accounts for every callable this value can reach."""
    return bool(value.entries) or not value.callables


def merge_entries(left: "Value", right: "Value") -> Tuple[Tuple[str, FrozenSet[CallableRef]], ...]:
    """Merge two key maps, keeping one only while it stays authoritative.

    A missing key reads as "no callable here", so a map that does not cover both
    sides would hide a sink. In that case drop it and let the caller fall back
    to the union.
    """
    if not left.entries and not right.entries:
        return ()
    if not maps_its_callables(left) or not maps_its_callables(right):
        return ()
    combined = left.entries + right.entries
    return combined if len(combined) <= MAX_ENTRIES else ()


def union_callables(values: Iterable["Value"]) -> FrozenSet[CallableRef]:
    refs: FrozenSet[CallableRef] = frozenset()
    for value in values:
        if value.callables:
            refs = refs | value.callables
    return limit_callables(refs)


def ordered_callables(value: "Value") -> Tuple[CallableRef, ...]:
    """Deterministic order, so findings do not depend on set iteration order."""
    return tuple(sorted(value.callables, key=CallableRef.sort_key))


@dataclass(frozen=True)
class Taint:
    labels: FrozenSet[str] = frozenset()
    confidence: Confidence = Confidence.HIGH
    trace: Tuple[TraceStep, ...] = ()
    cleared: FrozenSet[Category] = frozenset()
    weakened: FrozenSet[Category] = frozenset()
    parameters: FrozenSet[str] = frozenset()
    low_signal: bool = False

    def active_for(self, category: Category) -> bool:
        return category not in self.cleared

    def weak_for(self, category: Category) -> bool:
        return category in self.weakened

    def with_step(self, step: TraceStep) -> "Taint":
        if len(self.trace) >= MAX_TRACE_STEPS:
            return self
        if self.trace and self.trace[-1].line == step.line and self.trace[-1].kind == step.kind:
            return self
        return replace(self, trace=self.trace + (step,))

    def cleared_for(self, categories: FrozenSet[Category]) -> Optional["Taint"]:
        return replace(self, cleared=self.cleared | categories)

    def fully_cleared(self) -> "Taint":
        return replace(self, cleared=frozenset(Category))

    @property
    def neutralized(self) -> bool:
        return len(self.cleared) >= len(Category)

    def weakened_for(self, categories: FrozenSet[Category]) -> "Taint":
        return replace(self, weakened=self.weakened | categories)

    def downgraded(self) -> "Taint":
        if self.confidence <= Confidence.LOW:
            return self
        return replace(self, confidence=Confidence(int(self.confidence) - 10))

    def describe(self) -> str:
        if not self.labels:
            return "untrusted input"
        return ", ".join(sorted(self.labels))


def merge_taint(left: Optional[Taint], right: Optional[Taint]) -> Optional[Taint]:
    if left is None:
        return right
    if right is None:
        return left
    trace = left.trace if len(left.trace) >= len(right.trace) else right.trace
    return Taint(
        labels=left.labels | right.labels,
        confidence=max(left.confidence, right.confidence),
        trace=trace[:MAX_TRACE_STEPS],
        cleared=left.cleared & right.cleared,
        weakened=left.weakened | right.weakened,
        parameters=left.parameters | right.parameters,
        low_signal=left.low_signal and right.low_signal,
    )


@dataclass(frozen=True)
class Value:
    taint: Optional[Taint] = None
    constant: bool = False
    text_parts: Tuple[str, ...] = ()
    elements: Tuple["Value", ...] = ()
    is_sequence: bool = False
    sanitized: bool = False
    callables: FrozenSet[CallableRef] = frozenset()
    entries: Tuple[Tuple[str, FrozenSet[CallableRef]], ...] = ()
    # Lớp mà giá trị này là thể hiện ( tên đầy đủ, ví dụ
    # "app.services.items.ItemService" ), để `x.find(q)` tìm đúng phương thức
    # của lớp đó ở tệp khác. Rỗng khi không biết.
    instance: str = ""

    @property
    def text(self) -> str:
        return " ".join(self.text_parts)

    def tainted_for(self, category: Category) -> bool:
        return self.taint is not None and self.taint.active_for(category)

    def with_step(self, step: TraceStep) -> "Value":
        if self.taint is None:
            return self
        return replace(self, taint=self.taint.with_step(step))


UNKNOWN = Value()
CONSTANT = Value(constant=True)


def literal(text: str) -> Value:
    return Value(constant=True, text_parts=(text[:MAX_LITERAL_TEXT],))


def combine(*values: Value) -> Value:
    taint: Optional[Taint] = None
    constant = True
    sanitized = False
    parts: Tuple[str, ...] = ()
    for value in values:
        taint = merge_taint(taint, value.taint)
        constant = constant and value.constant
        sanitized = sanitized or value.sanitized
        if len(parts) < MAX_TEXT_PARTS:
            parts = parts + value.text_parts[: MAX_TEXT_PARTS - len(parts)]
    return Value(
        taint=taint,
        constant=constant and bool(values),
        text_parts=parts,
        sanitized=sanitized,
    )


def merge_values(left: Value, right: Value) -> Value:
    # This is the hottest path in the analyzer, and almost every value carries
    # no callable at all, so the empty cases are settled inline.
    left_refs = left.callables
    right_refs = right.callables
    if not left_refs:
        callables = right_refs
    elif not right_refs:
        callables = left_refs
    else:
        callables = limit_callables(left_refs | right_refs)
    entries = () if not left.entries and not right.entries else merge_entries(left, right)
    return Value(
        taint=merge_taint(left.taint, right.taint),
        constant=left.constant and right.constant,
        text_parts=(left.text_parts + right.text_parts)[:MAX_TEXT_PARTS],
        elements=(),
        is_sequence=left.is_sequence and right.is_sequence,
        sanitized=left.sanitized or right.sanitized,
        callables=callables,
        entries=entries,
        instance=left.instance or right.instance,
    )


Environment = Dict[str, Value]


def copy_environment(env: Environment) -> Environment:
    return dict(env)


def merge_environments(left: Environment, right: Environment) -> Environment:
    merged: Environment = {}
    for key in set(left) | set(right):
        left_value = left.get(key)
        right_value = right.get(key)
        if left_value is None:
            merged[key] = right_value if right_value is not None else UNKNOWN
        elif right_value is None:
            merged[key] = left_value
        else:
            merged[key] = merge_values(left_value, right_value)
    return merged


def environments_equal(left: Environment, right: Environment) -> bool:
    if set(left) != set(right):
        return False
    for key, value in left.items():
        other = right[key]
        left_taint = value.taint
        right_taint = other.taint
        if (left_taint is None) != (right_taint is None):
            return False
        if left_taint is not None and right_taint is not None:
            if left_taint.labels != right_taint.labels or left_taint.cleared != right_taint.cleared:
                return False
        if value.constant != other.constant:
            return False
        if value.callables != other.callables:
            return False
        if value.instance != other.instance:
            return False
    return True
