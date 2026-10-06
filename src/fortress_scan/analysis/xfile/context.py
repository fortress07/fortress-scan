"""Ngữ cảnh mà bộ phân tích token dùng để hỏi chỉ mục dự án khi đang chạy.

Một `FileContext` gắn với đúng một tệp và một chế độ:

* "report": lượt báo cáo bình thường, phẳng trên cả tệp. Lời gọi trỏ về hàm
  đã có summary thì summary được áp ngay tại lời gọi.
* "summary": đang tính summary cho MỘT hàm. Tham số mang vết nhiễm giả; vết
  đó chạm sink nào, chảy ra lời return nào thì ghi lại, không báo gì cả.
* "probe": như report nhưng chỉ để nhặt sự kiện ( đẩy job bẩn vào hàng đợi ),
  mọi phát hiện bị bỏ.
"""

from __future__ import annotations

from bisect import bisect_right
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from ...core.model import Category
from ..generic.lexer import NEWLINE, Token
from .model import Callee, FunctionDef, SinkHit, SourceReturn, Summary
from .project import QueueTaint, XProject

REPORT = "report"
SUMMARY = "summary"
PROBE = "probe"

# Khác None: "chưa tra" so với "đã tra, không có hàm nào bao".
_MISSING = object()


class FileContext:
    def __init__(
        self,
        project: XProject,
        path: str,
        tokens: Sequence[Token],
        mode: str = REPORT,
        function: Optional[FunctionDef] = None,
    ) -> None:
        self.project = project
        self.path = path
        self.mode = mode
        self.function = function
        self.facts = project.facts.get(path)
        self._tokens = tokens
        self.index = project.token_index(path, tokens)
        self._positions = self.index.positions
        # Bảng thân hàm dùng chung cho mọi FileContext của cùng một tệp:
        # `_reach[i]` là mút phải lớn nhất trong mọi hàm bắt đầu trước i, để
        # lúc dò ngược biết khi nào không còn hàm nào bao được vị trí đang hỏi.
        self._spans, self._starts, self._reach = project.function_spans(path)
        self._enclosing: Dict[int, Optional[FunctionDef]] = {}
        self.extra_sources: Dict[str, str] = project.extra_sources(path)
        self._resolve_cache: Dict[Tuple[str, str, int], List[Callee]] = {}
        self._constant_cache: Dict[Tuple[str, str], Optional[Tuple[str, str]]] = {}
        # Kết quả của chế độ summary.
        self.sink_hits: Set[SinkHit] = set()
        self.returns: Dict[int, FrozenSet[Category]] = {}
        self.source_return: Optional[SourceReturn] = None
        self.incomplete = False
        # Kết quả của chế độ probe.
        self.queue_events: List[Tuple[str, str, int]] = []

    @property
    def summarizing(self) -> bool:
        return self.mode == SUMMARY

    @property
    def probing(self) -> bool:
        return self.mode == PROBE

    def function_at(self, token: Optional[Token]) -> Optional[FunctionDef]:
        """Hàm trong cùng bao vị trí của token, hoặc hàm đang được tính summary.

        Tệp JS thật có hàng nghìn hàm và hàng chục nghìn lời gọi, nên quét
        thẳng danh sách hàm cho từng lời gọi là bậc hai: dò ngược từ hàm cuối
        bắt đầu trước vị trí đó, dừng khi mọi hàm còn lại đều kết thúc trước
        nó, rồi nhớ kết quả theo vị trí.
        """
        if token is None:
            return self.function
        index = self._positions.get((token.line, token.column))
        if index is None:
            return self.function
        found = self._enclosing.get(index, _MISSING)
        if found is _MISSING:
            found = None
            cursor = bisect_right(self._starts, index) - 1
            while cursor >= 0 and self._reach[cursor] > index:
                start, end, function = self._spans[cursor]
                if start <= index < end:
                    # Danh sách xếp theo mút trái tăng, nên hàm gặp đầu tiên
                    # khi dò ngược là hàm lồng trong cùng.
                    found = function
                    break
                cursor -= 1
            self._enclosing[index] = found
        return found or self.function

    def full_arguments(self, anchor: Token, chain: str) -> Optional[List[List[Token]]]:
        """Đối số của lời gọi đọc lại từ dòng token đầy đủ của tệp.

        Bộ phân tích cắt câu lệnh ở mọi dấu `{`, nên object literal làm đối số
        ( `res.render("v", { bio: x })` ) bị chặt làm đôi. Đọc lại từ vị trí
        thật của lời gọi thì đối số còn nguyên.
        """
        index = self._positions.get((anchor.line, anchor.column))
        if index is None:
            return None
        stream = self.index.stream
        separators = (".", "?.", "->", "::")
        _, after = stream.chain_at(index, separators)
        opener = stream.sig(after)
        if not stream.is_op(opener, "("):
            return None
        closing = stream.closing(opener)
        if closing < 0:
            return None
        return [
            [token for token in self._tokens[start:end] if token.kind != NEWLINE]
            for start, end in stream.split_commas(opener + 1, closing)
        ]

    @property
    def file_tokens(self) -> Sequence[Token]:
        return self._tokens

    def is_closure(self, function: FunctionDef, token: Optional[Token]) -> bool:
        """`function` lồng trong một hàm khác của tệp này, và lời gọi nằm trong hàm đó."""
        if function.path != self.path or self.facts is None or token is None:
            return False
        index = self._positions.get((token.line, token.column))
        if index is None:
            return False
        outer = self.project.enclosing_function(self.facts, function)
        return outer is not None and outer.body_start <= index < outer.body_end

    def resolve(self, chain: str, token: Optional[Token], argument_count: Optional[int]) -> List[Callee]:
        function = self.function_at(token)
        key = (chain, function.key if function is not None else "", -1 if argument_count is None else argument_count)
        cached = self._resolve_cache.get(key)
        if cached is not None:
            return cached
        callees = self.project.resolve(self.path, chain, function, argument_count)
        # Không áp summary của chính hàm đang được tính: đệ quy được xử lý bằng
        # vòng lặp tới điểm bất động ở tầng engine, không phải ở đây.
        if self.function is not None:
            callees = [item for item in callees if item.function.key != self.function.key]
        self._resolve_cache[key] = callees
        return callees

    def dispatch(self, table: str) -> List[Callee]:
        results: List[Callee] = []
        for target in self.project.js_dispatch(self.path, table):
            summary = self.project.summaries.get(target.key)
            if summary is not None:
                results.append(Callee(function=target, summary=summary, how="dispatch"))
        return results

    def constant(self, chain: str, token: Optional[Token]) -> Optional[Tuple[str, str]]:
        function = self.function_at(token)
        key = (chain, function.key if function is not None else "")
        if key in self._constant_cache:
            return self._constant_cache[key]
        value = self.project.constant(self.path, chain, function)
        self._constant_cache[key] = value
        return value

    def local_type(self, name: str, token: Optional[Token]) -> str:
        return self.project.declared_type(self.path, name, self.function_at(token))

    def config_value(self, key: str) -> Optional[Tuple[str, str]]:
        return self.project.config_value(key)

    def is_queue(self, name: str) -> Optional[str]:
        if self.facts is None:
            return None
        return self.facts.queues.get(name)

    def record_queue(self, queue_name: str, label: str, line: int) -> None:
        self.queue_events.append((queue_name, label, line))

    def summary(self) -> Summary:
        return Summary(
            sinks=frozenset(self.sink_hits),
            returns=dict(self.returns),
            source=self.source_return,
            complete=not self.incomplete,
        )


def apply_queue_events(project: XProject, path: str, events: Sequence[Tuple[str, str, int]]) -> bool:
    changed = False
    for queue_name, label, line in events:
        if queue_name not in project.tainted_queues:
            project.tainted_queues[queue_name] = QueueTaint(label=label, path=path, line=line)
            changed = True
    if changed:
        project.reset_source_cache()
    return changed
