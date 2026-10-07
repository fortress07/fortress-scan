"""Vai trò của một tệp trong dự án, suy ra từ đường dẫn tương đối.

Đây là bộ giảm false positive rẻ nhất và trung thực nhất mà một bộ phân tích
tĩnh có: cùng một hình dạng mã, `eval(payload)` trong `tests/fixtures/` và
`eval(payload)` trong `app/views.py` không đáng để người đọc dành cùng một
lượng thời gian. Quan trọng là bộ dò KHÔNG được im lặng vứt cái thứ nhất --
fixture vẫn chạy trên máy CI, vẫn là mã thật. Nó chỉ hạ độ tin cậy đúng một
nấc, nói ra vì sao, và để `--min-confidence` cho người dùng quyết định.

Phân loại chỉ nhìn chuỗi đường dẫn, không mở tệp và không hỏi hệ thống tệp:
nó chạy cho mọi ngôn ngữ, không tốn ngân sách phân tích, và không thêm một
đường đọc đĩa nào cho công cụ.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Optional, Tuple

from .model import PathContext

# Thư mục nào đóng vai trò gì. Khớp theo TỪNG THÀNH PHẦN đường dẫn, không phải
# substring: `contest/` không được thành `test`, `sample_rate.py` không được
# thành `samples`.
_TEST_DIRECTORIES: FrozenSet[str] = frozenset(
    {
        "test",
        "tests",
        "testing",
        "spec",
        "specs",
        "__tests__",
        "__test__",
        "testdata",
        "test_data",
        "fixtures",
        "fixture",
        "e2e",
        "integration_tests",
        "unittest",
        "unittests",
        "acceptance",
        "regress",
        "regression",
    }
)

_EXAMPLE_DIRECTORIES: FrozenSet[str] = frozenset(
    {
        "example",
        "examples",
        "sample",
        "samples",
        "demo",
        "demos",
        "playground",
        "sandbox",
        "tutorial",
        "tutorials",
        "cookbook",
        "recipes",
        "snippets",
        "benchmarks",
        "benchmark",
    }
)

_DOCUMENTATION_DIRECTORIES: FrozenSet[str] = frozenset(
    {"doc", "docs", "documentation", "website", "site", "man", "manual"}
)

_VENDOR_DIRECTORIES: FrozenSet[str] = frozenset(
    {
        "vendor",
        "vendored",
        "third_party",
        "thirdparty",
        "third-party",
        "external",
        "externals",
        "node_modules",
        "bower_components",
        "jspm_packages",
        "site-packages",
        "dist-packages",
        "eggs",
        ".eggs",
        "deps",
        "_vendor",
    }
)

_GENERATED_DIRECTORIES: FrozenSet[str] = frozenset(
    {
        "__generated__",
        "generated",
        "gen",
        "autogen",
        "migrations",
        "migrate",
        "proto_gen",
        "pb",
    }
)

# Quy ước đặt TÊN TỆP của từng hệ sinh thái. Một tệp có thể nằm ngoài thư mục
# test mà vẫn là test: `app/models_test.go`, `src/Foo.spec.ts`.
_TEST_PREFIXES: Tuple[str, ...] = ("test_", "tests_", "spec_", "it_")

# Hậu tố có dấu phân cách đứng trước: `api_test.go`, `Widget.spec.ts`.
_TEST_SUFFIXES: Tuple[str, ...] = (
    "_test",
    "_tests",
    "_spec",
    "_specs",
    ".test",
    ".tests",
    ".spec",
    ".specs",
    "-test",
    "-tests",
    "-spec",
    "-specs",
)

# Hậu tố dính liền theo kiểu camelCase, đúng quy ước của thế giới JVM:
# `UserServiceTest.java`, `PaymentIT.java`. Chỉ nhận khi chữ cái đứng trước là
# chữ thường hoặc chữ số -- tức là có một ranh giới từ thật.
#
# Không có phép kiểm ranh giới đó thì `latest.py`, `protest.py`, `contest.py`
# đều thành tệp kiểm thử, và mọi phát hiện trong chúng bị hạ mức trong im
# lặng. Một bộ phân loại sai theo hướng đó còn tệ hơn là không có: nó hạ mức
# đúng những tệp sản phẩm mà không ai nghĩ tới việc kiểm lại.
_CAMEL_TEST_SUFFIXES: Tuple[str, ...] = ("Test", "Tests", "Spec", "Specs", "IT")

# Tên tệp mà TOÀN BỘ phần thân là từ khoá: `test.py`, `spec.rb`.
_TEST_STEMS: FrozenSet[str] = frozenset({"test", "tests", "spec", "specs"})
_TEST_FILENAMES: FrozenSet[str] = frozenset(
    {"conftest.py", "setup_test.py", "karma.conf.js", "jest.config.js", "jest.setup.js"}
)

_GENERATED_SUFFIXES: Tuple[str, ...] = (
    "_pb2",
    "_pb2_grpc",
    "_pb",
    ".pb",
    ".g",
    # Dart: `schema.drift.dart` của drift, `user.freezed.dart` của freezed.
    ".drift",
    ".freezed",
    ".generated",
    ".min",
    ".bundle",
    "_generated",
)


# Một bảng tra thay cho năm phép `if ... in ...` nối nhau. Thứ tự ưu tiên khi
# một đường dẫn mang nhiều dấu hiệu vẫn giữ nguyên, chỉ là nó được quyết định
# bằng THỨ TỰ THÀNH PHẦN trong đường dẫn chứ không phải thứ tự các câu if:
# `vendor/x/tests/` gặp `vendor` trước nên vẫn là mã đi mượn, còn
# `tests/fixtures/vendor_stub.py` gặp `tests` trước nên vẫn là test.
def _build_directory_roles() -> Dict[str, PathContext]:
    roles: Dict[str, PathContext] = {}
    for names, role in (
        (_VENDOR_DIRECTORIES, PathContext.VENDORED),
        (_GENERATED_DIRECTORIES, PathContext.GENERATED),
        (_TEST_DIRECTORIES, PathContext.TEST),
        (_EXAMPLE_DIRECTORIES, PathContext.EXAMPLE),
        (_DOCUMENTATION_DIRECTORIES, PathContext.DOCUMENTATION),
    ):
        for name in names:
            # setdefault: một cái tên có mặt ở hai bảng thì bảng ĐỨNG TRƯỚC
            # thắng, đúng như thứ tự các câu if cũ.
            roles.setdefault(name, role)
    return roles


_DIRECTORY_ROLES: Dict[str, PathContext] = _build_directory_roles()


def _stem(name: str) -> str:
    """Tên tệp bỏ đúng MỘT phần mở rộng cuối, giữ nguyên phần còn lại.

    `Foo.spec.ts` phải còn `Foo.spec` để hậu tố `.spec` khớp được; cắt hết mọi
    dấu chấm thì `app.config.js` cũng biến thành `app` và mọi quy ước đặt tên
    theo kiểu `<tên>.<vai trò>.<đuôi>` mất chỗ bám.
    """
    head, dot, _extension = name.rpartition(".")
    if not dot or not head:
        return name
    return head


def _looks_like_test(stem: str) -> bool:
    lowered = stem.lower()
    if lowered in _TEST_STEMS:
        return True
    if lowered.startswith(_TEST_PREFIXES):
        return True
    if lowered.endswith(_TEST_SUFFIXES):
        return True
    for suffix in _CAMEL_TEST_SUFFIXES:
        if not stem.endswith(suffix) or len(stem) <= len(suffix):
            continue
        previous = stem[-len(suffix) - 1]
        if previous.islower() or previous.isdigit():
            return True
    return False


def _looks_generated(stem: str) -> bool:
    return stem.lower().endswith(_GENERATED_SUFFIXES)


def classify(relative_path: str) -> PathContext:
    """Vai trò của tệp, ưu tiên nhãn "ít khẩn nhất" khi có nhiều dấu hiệu.

    Thứ tự quyết định là cố ý: `vendor/x/tests/` vẫn là mã đi mượn ( người
    dùng không sửa được nó ), còn `tests/fixtures/vendor_stub.py` vẫn là test.
    Thành phần đứng TRƯỚC trong đường dẫn nói to hơn, nên vòng lặp dừng ở dấu
    hiệu đầu tiên gặp được thay vì gom hết rồi xếp hạng.
    """
    normalized = relative_path.replace("\\", "/").strip("/")
    if not normalized:
        return PathContext.PRODUCTION
    parts = [part for part in normalized.split("/") if part and part != "."]
    if not parts:
        return PathContext.PRODUCTION

    for part in parts[:-1]:
        by_directory = _DIRECTORY_ROLES.get(part.lower())
        if by_directory is not None:
            return by_directory
    return _classify_filename(parts[-1])


def _classify_filename(name: str) -> PathContext:
    if name in _TEST_FILENAMES:
        return PathContext.TEST
    stem = _stem(name)
    if _looks_generated(stem):
        return PathContext.GENERATED
    if _looks_like_test(stem):
        return PathContext.TEST
    return PathContext.PRODUCTION


# Ngữ cảnh nào hạ độ tin cậy, và câu giải thích đi kèm phát hiện. Đúng MỘT nấc
# cho mọi ngữ cảnh: hạ sâu hơn thì một lỗ hổng thật trong thư mục examples/ --
# thứ vẫn được sao chép nguyên xi vào sản phẩm thật -- tụt xuống dưới mọi
# ngưỡng lọc và biến mất, mà đó lại chính là kiểu bỏ sót nguy hiểm nhất.
_DEMOTION_REASONS = {
    PathContext.TEST: "tệp nằm trong phần kiểm thử của dự án nên ít có khả năng chạy trong sản phẩm",
    PathContext.EXAMPLE: "tệp là ví dụ hoặc mẫu minh hoạ, không phải đường chạy chính",
    PathContext.DOCUMENTATION: "tệp thuộc phần tài liệu",
    PathContext.GENERATED: "tệp do máy sinh ra nên phải sửa ở nguồn sinh, không sửa tại chỗ",
    PathContext.VENDORED: "tệp là mã đi mượn từ bên thứ ba, sửa được ở phía thượng nguồn",
}


def demotion_reason(context: PathContext) -> Optional[str]:
    return _DEMOTION_REASONS.get(context)
