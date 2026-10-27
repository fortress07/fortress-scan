"""Chỉ mục hàm dùng chung giữa các tệp Python của cùng một lượt quét.

Phân tích taint từng tệp ( 0.1 ) không thấy dữ liệu bẩn rời khỏi tệp nó đi
vào: một handler gọi helper ở tệp khác thì sink nằm trong helper không bao
giờ được báo. Module này giữ phần "summary" của mọi hàm trong dự án -- tham
số nào chảy tới sink nào, tham số nào sống sót qua lời return -- để lượt
phân tích của tệp gọi áp được summary đó như áp summary của hàm cùng tệp.

Ngoài hàm, chỉ mục còn giữ lớp ( lớp cha, kiểu của thuộc tính, tên phương
thức ) và bảng import của từng module, để `service.search(x)` tìm được
`ItemService.search` dù lớp được xuất lại qua `services/__init__.py` và
phương thức thật nằm ở lớp cha trong tệp thứ ba.

Summary được tính riêng cho từng tệp rồi ghép lại, nên engine lặp: mỗi vòng
dựng lại chỉ mục từ kết quả vòng trước và chỉ tính lại những tệp có câu hỏi
nhận câu trả lời khác ( xem `ask` ). Hết tệp phải tính lại là đã tới điểm
dừng; số vòng có chặn trên để dự án lớn không chạy mãi.
"""

from __future__ import annotations

import builtins
from typing import Dict, FrozenSet, Iterable, Mapping, Optional, Set, Tuple

from .analyzer import ClassRecord, FunctionInfo, Summary
from .imports import module_names

# Dấu nhận diện cho node của hàm ở tệp khác: không bao giờ trùng với một
# ast.AST thật cũng như None, để bộ chống đệ quy ( "đừng áp summary của
# chính hàm đang xét" ) không nhầm nó với hàm cục bộ.
FOREIGN_NODE = object()

MAX_INDEX_MODULES = 5000
MAX_INDEX_FUNCTIONS = 20000
MAX_INDEX_CLASSES = 20000
# Chuỗi re-export / kế thừa đi sâu tới đâu thì dừng ( chống vòng lặp ).
_MAX_HOPS = 8

# Tên trần trùng một builtin thì không bao giờ được tra qua chỉ mục dự án.
# `map(...)` trong tệp không import `map` là builtin, chứ không phải `Style.map`
# của tkinter. Nối nhầm hai thứ đó làm taint thật bị vứt, và phát hiện tụt từ
# FSB-EXEC-001 xuống FSB-EXEC-002: bật phân tích xuyên file lại làm kết quả yếu
# đi. Hàm người dùng tự đặt trùng tên builtin vẫn chạy bình thường, vì
# `from helpers import map` được phân giải thành `helpers.map` nên đi đường
# dotted.
_BUILTIN_NAMES: FrozenSet[str] = frozenset(dir(builtins))


class ProjectIndex:
    """Bảng summary hàm của toàn dự án, tra theo tên import hoặc tên đơn."""

    def __init__(self) -> None:
        self._dotted: Dict[str, FunctionInfo] = {}
        self._simple: Dict[str, FunctionInfo] = {}
        # Tên đã từng đụng độ phải ở lại "mập mờ" VĨNH VIỄN. Trước đây đụng độ
        # chỉ được xử lý bằng cách xóa khóa cuối mỗi lần register, nên module
        # thứ ba dùng lại tên đó tạo lại khóa với đúng một phần tử và giành
        # được liên kết: 3 module cùng định nghĩa `run` thì `run` trỏ về module
        # cuối, 4 module thì lại sạch - sai theo tính chẵn lẻ. Tên phổ biến
        # ( run, query, execute, handle ) đụng nhau khắp mọi repo thật, và cái
        # giá là taint xuyên file quy sink về NHẦM tệp.
        self._ambiguous_dotted: Set[str] = set()
        self._ambiguous_simple: Set[str] = set()
        # Lớp: mọi biến thể tên đầy đủ -> khóa chuẩn ( biến thể dài nhất ).
        self._class_names: Dict[str, str] = {}
        self._ambiguous_classes: Set[str] = set()
        self._classes: Dict[str, ClassRecord] = {}
        # Tên mà mỗi module nhập vào, để đi theo re-export: `pkg.Service` ->
        # `pkg.service.Service` khi pkg/__init__.py viết `from .service import Service`.
        self._module_aliases: Dict[str, Mapping[str, str]] = {}
        self._ambiguous_modules: Set[str] = set()
        # Chỉ mục không đổi sau khi dựng xong, nên kết quả đi theo alias được
        # nhớ lại; ghi dict từ nhiều luồng là an toàn dưới GIL.
        self._alias_cache: Dict[str, str] = {}
        self.functions_registered = 0
        self.modules_registered = 0
        self.classes_registered = 0
        self.full = False
        # Engine đặt False khi hết số vòng mà vẫn còn tệp chưa ổn định.
        self.converged = True

    @staticmethod
    def _bind(
        table: Dict[str, FunctionInfo],
        ambiguous: Set[str],
        key: str,
        info: FunctionInfo,
    ) -> None:
        """Giữ liên kết chỉ khi tên còn trỏ về đúng một hàm."""
        if key in ambiguous:
            return
        current = table.get(key)
        if current is None:
            table[key] = info
        elif current is not info:
            # Một tên trỏ về nhiều hàm khác nhau thì mọi liên kết theo tên đó
            # đều mất giá trị: bỏ hẳn thay vì đoán mò một bên.
            del table[key]
            ambiguous.add(key)

    @staticmethod
    def _bind_value(table: Dict[str, object], ambiguous: Set[str], key: str, value: object) -> None:
        """Như `_bind`, cho giá trị so bằng nội dung ( khóa lớp, bảng import )."""
        if key in ambiguous:
            return
        current = table.get(key)
        if current is None:
            table[key] = value
        elif current is not value and current != value:
            del table[key]
            ambiguous.add(key)

    def register(
        self,
        relative_path: str,
        functions: Dict[str, FunctionInfo],
        summaries: Dict[str, Summary],
        classes: Iterable[ClassRecord] = (),
        aliases: Optional[Mapping[str, str]] = None,
    ) -> None:
        names = module_names(relative_path)
        if not names:
            return
        if aliases:
            for module_name in names:
                self._bind_value(self._module_aliases, self._ambiguous_modules, module_name, aliases)
        for record in classes:
            if self.classes_registered >= MAX_INDEX_CLASSES:
                self.full = True
                break
            key = "%s.%s" % (names[0], record.qualname)
            if key in self._classes:
                continue
            self._classes[key] = record
            self.classes_registered += 1
            for module_name in names:
                self._bind_value(
                    self._class_names,
                    self._ambiguous_classes,
                    "%s.%s" % (module_name, record.qualname),
                    key,
                )
        if not functions:
            return
        if (
            self.modules_registered >= MAX_INDEX_MODULES
            or self.functions_registered >= MAX_INDEX_FUNCTIONS
        ):
            self.full = True
            return
        self.modules_registered += 1
        for qualname, info in sorted(functions.items()):
            if self.functions_registered >= MAX_INDEX_FUNCTIONS:
                self.full = True
                break
            summary = summaries.get(qualname)
            if summary is None or not summary.sinks and not summary.returns and not summary.instance:
                # Hàm không chạm sink, không trả về taint, cũng không trả về
                # đối tượng của lớp nào thì áp summary hay không cũng vậy.
                continue
            foreign = FunctionInfo(
                node=FOREIGN_NODE,
                qualname=qualname,
                simple_name=info.simple_name,
                parameters=info.parameters,
                handler_sources={},
                summary=summary,
                origin_path=relative_path.replace("\\", "/"),
            )
            if info.simple_name not in _BUILTIN_NAMES:
                self._bind(self._simple, self._ambiguous_simple, info.simple_name, foreign)
            for module_name in names:
                self._bind(
                    self._dotted,
                    self._ambiguous_dotted,
                    "%s.%s" % (module_name, qualname),
                    foreign,
                )
            self.functions_registered += 1

    def lookup(
        self, qualname: Optional[str], *, allow_simple: bool = True
    ) -> Optional[FunctionInfo]:
        """Tra hàm theo tên import; `allow_simple` bật tra thêm theo tên trần.

        Đường dotted ( `helpers.run_cmd` ) là liên kết có căn cứ import nên
        luôn được tra. Tên trần thì chỉ dành cho lời gọi `run_cmd(...)` không
        qua attribute: áp nó cho `cp.read(...)` là gán nguồn gốc sai cho một
        lời gọi phương thức trên đối tượng vô danh.
        """
        if not qualname:
            return None
        exact = self._function(qualname)
        if exact is not None:
            return exact
        if not allow_simple:
            return None
        return self._simple.get(qualname.rsplit(".", 1)[-1])

    def _function(self, dotted: str) -> Optional[FunctionInfo]:
        """Hàm theo tên dotted, đi theo re-export của module nếu cần."""
        name = dotted
        for _ in range(_MAX_HOPS):
            found = self._dotted.get(name)
            if found is not None:
                return found
            if name in self._ambiguous_dotted:
                return None
            name = self._follow_alias(name)
            if not name:
                return None
        return None

    def _follow_alias(self, dotted: str) -> str:
        """`pkg.Service` -> `pkg.service.Service` nếu module `pkg` nhập Service từ đó.

        Module dài nhất khớp tiền tố quyết định: tên nằm trong module đó mà
        không phải tên nhập vào thì nó được định nghĩa ngay tại đấy, không có
        gì để đi tiếp.
        """
        cached = self._alias_cache.get(dotted)
        if cached is not None:
            return cached
        resolved = ""
        parts = dotted.split(".")
        for cut in range(len(parts) - 1, 0, -1):
            aliases = self._module_aliases.get(".".join(parts[:cut]))
            if aliases is None:
                continue
            target = aliases.get(parts[cut])
            if target:
                resolved = ".".join([target] + parts[cut + 1 :])
                if resolved == dotted:
                    resolved = ""
            break
        self._alias_cache[dotted] = resolved
        return resolved

    def class_key(self, dotted: Optional[str]) -> str:
        """Khóa chuẩn của lớp mà `dotted` trỏ tới, hoặc "" nếu không rõ / mập mờ."""
        name = dotted or ""
        for _ in range(_MAX_HOPS):
            if not name or name in self._ambiguous_classes:
                return ""
            key = self._class_names.get(name)
            if key:
                return key
            name = self._follow_alias(name)
        return ""

    def find_method(self, key: str, name: str) -> Optional[FunctionInfo]:
        """Phương thức `name` của lớp `key`, đi lên lớp cha khi lớp không tự định nghĩa nó."""
        seen: Set[str] = set()
        current = key
        pending = [key]
        while pending and len(seen) < _MAX_HOPS:
            current = pending.pop(0)
            if current in seen:
                continue
            seen.add(current)
            record = self._classes.get(current)
            if record is None:
                continue
            if name in record.methods:
                # Lớp tự định nghĩa phương thức: summary trống ( vô hại ) thì
                # không có trong chỉ mục, và lớp cha không được thế chỗ nó.
                return self._dotted.get("%s.%s" % (current, name))
            pending.extend(base for base in (self.class_key(item) for item in record.bases) if base)
        return None

    def attribute_type(self, key: str, attribute: str) -> str:
        """Lớp của `obj.attribute` khi `obj` thuộc lớp `key`, hoặc ""."""
        seen: Set[str] = set()
        pending = [key]
        while pending and len(seen) < _MAX_HOPS:
            current = pending.pop(0)
            if current in seen:
                continue
            seen.add(current)
            record = self._classes.get(current)
            if record is None:
                continue
            for name, candidates in record.attributes:
                if name != attribute:
                    continue
                for candidate in candidates:
                    found = self.class_key(candidate) or self._instance_of(candidate)
                    if found:
                        return found
            pending.extend(base for base in (self.class_key(item) for item in record.bases) if base)
        return ""

    def _instance_of(self, dotted: str) -> str:
        function = self._function(dotted)
        if function is None or function.summary is None:
            return ""
        return function.summary.instance

    def ask(self, query: Tuple[str, ...]):
        """Một câu hỏi của pha thu thập, dạng bộ để engine hỏi lại được ở vòng sau."""
        kind = query[0]
        if kind == "function":
            return self.lookup(query[1], allow_simple=query[2] == "simple")
        if kind == "class":
            return self.class_key(query[1])
        if kind == "method":
            return self.find_method(query[1], query[2])
        if kind == "attribute":
            return self.attribute_type(query[1], query[2])
        raise ValueError("unknown project query %r" % (kind,))

    def agrees(self, answers: Mapping[Tuple[str, ...], object]) -> bool:
        """Mọi câu trả lời cũ còn đúng với chỉ mục này không ( thì khỏi tính lại tệp )."""
        return all(self.ask(query) == answer for query, answer in answers.items())
