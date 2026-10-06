"""Dữ liệu dùng chung của phân tích xuyên file: hàm, lớp, tệp và summary."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple

from ...core.model import Category

# Số thứ tự tham số giả cho `this`/receiver không cần: phương thức nhận đối số
# đúng như lời gọi viết, receiver nằm ở chuỗi truy cập chứ không ở danh sách.


@dataclass(frozen=True)
class FunctionDef:
    path: str
    name: str
    owner: str
    params: Tuple[str, ...]
    param_types: Tuple[str, ...]
    # Nhãn nguồn của tham số do framework bơm vào ( @RequestParam, @Query(),
    # @KafkaListener... ); None nghĩa là tham số bình thường.
    param_sources: Tuple[Optional[str], ...]
    body_start: int
    body_end: int
    line: int
    return_type: str = ""
    expression_body: bool = False
    variadic: bool = False
    # Tên mà framework dùng để gọi tham số ( @Param("name") của MyBatis ).
    param_aliases: Tuple[str, ...] = ()
    # Phương thức không có thân ( interface, abstract ): summary của nó đến
    # từ lớp hiện thực hoặc từ mapper SQL, không đến từ chính nó.
    abstract: bool = False
    # Chú thích / decorator đặt trên chính hàm, không kèm '@'.
    annotations: Tuple[str, ...] = ()

    @property
    def qualname(self) -> str:
        return "%s.%s" % (self.owner, self.name) if self.owner else self.name

    @property
    def key(self) -> str:
        return "%s::%s@%d" % (self.path, self.qualname, self.line)

    @property
    def display(self) -> str:
        return self.qualname


@dataclass
class ClassDef:
    path: str
    name: str
    bases: Tuple[str, ...] = ()
    is_interface: bool = False
    fields: Dict[str, str] = field(default_factory=dict)
    methods: Dict[str, List[FunctionDef]] = field(default_factory=dict)
    # Trường Java gắn @Value("${khoa}"): tên trường -> khóa cấu hình.
    config_fields: Dict[str, str] = field(default_factory=dict)
    constants: Dict[str, str] = field(default_factory=dict)
    # Tên đầy đủ ( Java: gói + tên lớp; Go: thư mục + tên kiểu ).
    qualified: str = ""


@dataclass(frozen=True)
class ImportBinding:
    """Tên cục bộ trỏ về một thứ được xuất ra ở module khác.

    `name` là "*" cho cả module ( namespace / require ), "default" cho phần xuất
    mặc định, còn lại là tên được xuất.
    """

    spec: str
    name: str


@dataclass
class FileFacts:
    path: str
    language: str
    functions: List[FunctionDef] = field(default_factory=list)
    classes: Dict[str, ClassDef] = field(default_factory=dict)
    imports: Dict[str, ImportBinding] = field(default_factory=dict)
    # tên được xuất -> tên cục bộ ( qualname của hàm, tên lớp, tên object ).
    exports: Dict[str, str] = field(default_factory=dict)
    # ( spec, tên ở module kia hoặc "*", tên xuất ở đây hoặc "*" )
    reexports: List[Tuple[str, str, str]] = field(default_factory=list)
    package: str = ""
    # Java: các gói import kiểu `a.b.*`; Go: alias -> đường dẫn import.
    wildcard_imports: List[str] = field(default_factory=list)
    static_imports: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    constants: Dict[str, str] = field(default_factory=dict)
    # Object literal đặt tên: tên -> {khóa -> tên cục bộ / qualname của hàm}.
    objects: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # Kiểu của biến ở cấp module ( `const svc = new Service()` ).
    module_types: Dict[str, str] = field(default_factory=dict)
    # Kiểu trì hoãn: biến được gán bằng giá trị trả về của một lời gọi.
    module_deferred: Dict[str, str] = field(default_factory=dict)
    # Các hàm xử lý route: chuỗi truy cập trỏ về handler ( qua tham số đầu ).
    route_handlers: List[Tuple[str, int]] = field(default_factory=list)
    # Hàng đợi: tên biến -> tên hàng đợi; nơi xử lý: (tên hàng đợi, vị trí token
    # đầu thân hàm, tên tham số job).
    queues: Dict[str, str] = field(default_factory=dict)
    queue_consumers: List[Tuple[str, int, str]] = field(default_factory=list)
    # Tệp JSON/thuộc tính được nạp như module: tên cục bộ -> đường dẫn tệp.
    data_imports: Dict[str, str] = field(default_factory=dict)
    # Kiểu biến cục bộ trong từng hàm ( theo FunctionDef.key ).
    envs: Dict[str, Dict[str, str]] = field(default_factory=dict)
    deferred: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # Đối tượng request do framework truyền vào: (đầu, cuối, tên, kiểu).
    request_objects: List[Tuple[int, int, str, str]] = field(default_factory=list)
    # SQL viết thẳng trong chú thích ( @Select("... ${x} ...") của MyBatis ).
    inline_sql: List[Tuple[FunctionDef, str, int, int]] = field(default_factory=list)
    # Nơi đẩy job vào hàng đợi: (tên biến hàng đợi, vị trí token của lời gọi).
    queue_producers: List[Tuple[str, int]] = field(default_factory=list)
    # Bảng điều phối: tên object -> danh sách qualname của hàm trong đó.
    dispatch_tables: Dict[str, Tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class SinkHit:
    param: int
    rule_id: str
    category: Category
    line: int
    column: int
    symbol: str
    description: str
    path: str
    # Chuỗi hàm trung gian, để thông điệp nói được dữ liệu đi qua đâu.
    via: Tuple[str, ...] = ()
    # Sink SQL chỉ nhận ra được khi biết câu lệnh là SQL: hàm bọc `query(sql)`
    # không tự mang chữ SELECT nào, nên phải để nơi gọi chứng minh điều đó.
    requires_sql: bool = False


@dataclass(frozen=True)
class SourceReturn:
    label: str
    line: int
    path: str


@dataclass
class Summary:
    sinks: FrozenSet[SinkHit] = frozenset()
    # tham số -> những nhóm đã được khử trên đường tới lời return.
    returns: Dict[int, FrozenSet[Category]] = field(default_factory=dict)
    source: Optional[SourceReturn] = None
    complete: bool = True

    def same_as(self, other: Optional["Summary"]) -> bool:
        if other is None:
            return False
        return (
            self.sinks == other.sinks
            and self.returns == other.returns
            and self.source == other.source
            and self.complete == other.complete
        )

    @property
    def empty(self) -> bool:
        return not self.sinks and not self.returns and self.source is None


@dataclass(frozen=True)
class Callee:
    function: FunctionDef
    summary: Summary
    # Phân giải theo cách nào: "import", "local", "type", "interface"...
    how: str = ""
