from __future__ import annotations

import ast
from typing import Dict, FrozenSet, List, Optional, Tuple

_MAX_CHAIN_DEPTH = 12


def module_names(relative_path: str) -> Tuple[str, ...]:
    """Những tên module mà một tệp có thể được import dưới, từ dài nhất.

    ``app/services/helpers.py`` import được dưới dạng ``app.services.helpers``,
    ``services.helpers`` hay ``helpers`` tùy sys.path của dự án, nên đăng ký
    cả ba; xung đột tên sẽ bị loại ở ``register`` theo hướng bảo toàn.

    Thư mục mang tên không phải định danh ( ``my-app/`` ) không thể nằm trong
    tên module, nên chỉ phần đuôi sau nó được tính: repo quét từ thư mục cha
    vẫn có tên module cho mọi tệp bên trong.
    """
    parts = relative_path.replace("\\", "/").strip("/").split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        return ()
    stem = parts[-1]
    if stem == "__init__.py":
        stem_parts = parts[:-1]
    elif stem.endswith(".py"):
        stem_parts = parts[:-1] + [stem[: -len(".py")]]
    else:
        return ()
    start = len(stem_parts)
    while start > 0 and stem_parts[start - 1].isidentifier():
        start -= 1
    stem_parts = stem_parts[start:]
    if not stem_parts:
        return ()
    return tuple(
        ".".join(stem_parts[index:]) for index in range(len(stem_parts))
    )


def package_of(relative_path: str) -> str:
    """Gói chứa module này, theo tên dài nhất: nơi `from . import x` trỏ tới."""
    names = module_names(relative_path)
    if not names:
        return ""
    if relative_path.replace("\\", "/").endswith("__init__.py"):
        return names[0]
    return names[0].rpartition(".")[0]


class ImportResolver:
    def __init__(self, package: str = "") -> None:
        self._aliases: Dict[str, str] = {}
        # Gói của tệp đang xét, để `from ..db import repo` thành tên tuyệt đối
        # ( `app.db.repo` ) thay vì tên cụt `db.repo` dễ trùng giữa các gói.
        self._package = package

    def collect(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self._add_import(node)
            elif isinstance(node, ast.ImportFrom):
                self._add_import_from(node)

    def _add_import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self._aliases[alias.asname] = alias.name
            else:
                head = alias.name.split(".", 1)[0]
                self._aliases.setdefault(head, head)

    def _add_import_from(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if node.level:
            base = self._relative_base(node.level)
            if base:
                module = "%s.%s" % (base, module) if module else base
            elif not module:
                return
        for alias in node.names:
            if alias.name == "*":
                continue
            target = "%s.%s" % (module, alias.name) if module else alias.name
            self._aliases[alias.asname or alias.name] = target

    def _relative_base(self, level: int) -> str:
        if not self._package:
            return ""
        parts = self._package.split(".")
        drop = level - 1
        if drop >= len(parts):
            return ""
        return ".".join(parts[: len(parts) - drop])

    def aliases(self) -> Dict[str, str]:
        return dict(self._aliases)

    def resolve(self, dotted: str) -> str:
        if not dotted:
            return dotted
        head, _, rest = dotted.partition(".")
        mapped = self._aliases.get(head)
        if mapped is None:
            return dotted
        return "%s.%s" % (mapped, rest) if rest else mapped

    def qualname_of(self, node: ast.AST) -> Optional[str]:
        dotted = dotted_name(node)
        if dotted is None:
            return None
        return self.resolve(dotted)

    def is_alias_of(self, name: str, target: str) -> bool:
        return self._aliases.get(name) == target

    def imports_any(self, roots: FrozenSet[str]) -> bool:
        """Tệp này có nhập gì từ một trong những gói cấp cao nhất đó không."""
        for target in self._aliases.values():
            if target.split(".", 1)[0] in roots:
                return True
        return False


def dotted_name(node: ast.AST, depth: int = 0) -> Optional[str]:
    if depth > _MAX_CHAIN_DEPTH:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value, depth + 1)
        if base is None:
            return None
        return "%s.%s" % (base, node.attr)
    if isinstance(node, ast.Call):
        return dotted_name(node.func, depth + 1)
    return None


def attribute_parts(node: ast.AST) -> List[str]:
    dotted = dotted_name(node)
    return dotted.split(".") if dotted else []
