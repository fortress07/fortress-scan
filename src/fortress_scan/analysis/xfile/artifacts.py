"""Tệp không phải mã mà luồng dữ liệu vẫn đi qua: template, mapper SQL, cấu hình.

Mọi phép đọc ở đây là quét chuỗi có chặn trên ( str.find với giới hạn độ dài ),
không dùng regex có quantifier lồng nhau: tệp được quét là của người lạ.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Dict, List, Optional, Tuple

MAX_ARTIFACT_BYTES = 1_000_000
MAX_ARTIFACTS = 20_000
_MAX_EXPRESSION = 400

TEMPLATE_SUFFIXES = (
    ".ejs",
    ".hbs",
    ".handlebars",
    ".mustache",
    ".pug",
    ".jade",
    ".njk",
    ".nunjucks",
    ".jinja",
    ".jinja2",
    ".j2",
    ".html",
    ".htm",
    ".twig",
)
CONFIG_SUFFIXES = (".properties", ".yml", ".yaml", ".json", ".xml")
SPECIAL_NAMES = ("go.mod",)


def is_artifact_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in SPECIAL_NAMES:
        return True
    if lowered.endswith(".min.js") or lowered == "package-lock.json":
        return False
    return lowered.endswith(TEMPLATE_SUFFIXES) or lowered.endswith(CONFIG_SUFFIXES)


@dataclass(frozen=True)
class RawOutput:
    """Một chỗ template in giá trị ra mà không escape."""

    root: str
    line: int
    column: int
    syntax: str


@dataclass
class TemplateInfo:
    path: str
    outputs: List[RawOutput] = field(default_factory=list)
    # Toàn bộ template tắt escape ( `{% autoescape false %}` bao trùm ).
    unescaped_all: bool = False


@dataclass(frozen=True)
class MapperStatement:
    namespace: str
    statement_id: str
    roots: Tuple[str, ...]
    line: int
    column: int
    path: str


def _line_col(text: str, offset: int) -> Tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    start = text.rfind("\n", 0, offset) + 1
    return line, offset - start


def _root_of(expression: str) -> str:
    """Biến gốc của một biểu thức template: `user.bio | safe` -> `user`."""
    text = expression.strip()
    for prefix in ("locals.", "data.", "it.", "this.", "model.", "@root."):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    name = []
    for char in text:
        if char.isalnum() or char in "_$":
            name.append(char)
        else:
            break
    return "".join(name)


def _scan_pairs(text: str, opener: str, closer: str):
    """Sinh (vị trí, nội dung) của mọi cặp opener...closer ngắn hơn giới hạn."""
    cursor = 0
    limit = len(text)
    while cursor < limit:
        start = text.find(opener, cursor)
        if start < 0:
            return
        inner_start = start + len(opener)
        end = text.find(closer, inner_start, inner_start + _MAX_EXPRESSION)
        if end < 0:
            cursor = inner_start
            continue
        yield start, text[inner_start:end]
        cursor = end + len(closer)


def parse_template(relative: str, text: str) -> TemplateInfo:
    info = TemplateInfo(path=relative)
    lowered = relative.lower()
    outputs = info.outputs

    def add(offset: int, expression: str, syntax: str) -> None:
        root = _root_of(expression)
        if root and not root[0].isdigit():
            line, column = _line_col(text, offset)
            outputs.append(RawOutput(root, line, column, syntax))

    if lowered.endswith(".ejs"):
        for offset, inner in _scan_pairs(text, "<%-", "%>"):
            add(offset, inner, "<%- %>")
    if lowered.endswith((".hbs", ".handlebars", ".mustache", ".html", ".htm")):
        for offset, inner in _scan_pairs(text, "{{{", "}}}"):
            add(offset, inner, "{{{ }}}")
        for offset, inner in _scan_pairs(text, "{{&", "}}"):
            add(offset, inner, "{{& }}")
    if lowered.endswith((".pug", ".jade")):
        for offset, inner in _scan_pairs(text, "!{", "}"):
            add(offset, inner, "!{ }")
        for line_number, line_text in enumerate(text.split("\n"), 1):
            position = line_text.find("!= ")
            if position < 0:
                position = line_text.find("!=")
            if position >= 0 and position < 200:
                before = line_text[:position].strip()
                if before and not before.startswith(("-", "if ", "unless ")):
                    root = _root_of(line_text[position + 2 :])
                    if root:
                        outputs.append(RawOutput(root, line_number, position, "!="))
    if lowered.endswith((".njk", ".nunjucks", ".jinja", ".jinja2", ".j2", ".html", ".htm", ".twig")):
        for offset, inner in _scan_pairs(text, "{{", "}}"):
            if inner.startswith(("{", "&")):
                continue
            pipes = [part.strip() for part in inner.split("|")[1:]]
            if any(part in ("safe", "raw") or part.startswith(("safe ", "raw ")) for part in pipes):
                add(offset, inner.split("|", 1)[0], "| safe")
        off = text.find("{% autoescape false %}")
        if off < 0:
            off = text.find("{%autoescape false%}")
        if off >= 0:
            end = text.find("{% endautoescape %}", off)
            region_end = end if end >= 0 else len(text)
            for offset, inner in _scan_pairs(text[off:region_end], "{{", "}}"):
                add(off + offset, inner.split("|", 1)[0], "autoescape false")
    if lowered.endswith((".html", ".htm")):
        # Thymeleaf: th:utext và inline không escape `[( ... )]`.
        for marker in ('th:utext="', "th:utext='"):
            for offset, inner in _scan_pairs(text, marker, marker[-1]):
                if "${" in inner:
                    add(offset, inner.split("${", 1)[1], "th:utext")
        for offset, inner in _scan_pairs(text, "[(${", "})]"):
            add(offset, inner, "[( )]")
    return info


def template_keys(relative: str) -> List[str]:
    """Những tên mà mã nguồn có thể dùng để gọi template này.

    `src/views/users/show.ejs` được gọi là `users/show`, `users/show.ejs`, và
    nếu thư mục render là `src/views` thì đó là tên duy nhất có nghĩa. Không
    biết thư mục render là gì nên đăng ký mọi hậu tố.
    """
    path = PurePosixPath(relative.replace("\\", "/"))
    parts = list(path.parts)
    keys: List[str] = []
    stem = path.name
    for suffix in TEMPLATE_SUFFIXES:
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    parts_without_ext = parts[:-1] + [stem]
    for index in range(len(parts)):
        keys.append("/".join(parts[index:]))
        keys.append("/".join(parts_without_ext[index:]))
    return keys


def parse_mybatis(relative: str, text: str) -> List[MapperStatement]:
    if "<mapper" not in text:
        return []
    statements: List[MapperStatement] = []
    namespace = ""
    head = text.find("<mapper")
    ns = text.find("namespace=", head, head + 2000)
    if ns >= 0:
        quote = text[ns + len("namespace=")] if ns + len("namespace=") < len(text) else '"'
        end = text.find(quote, ns + len("namespace=") + 1, ns + 400)
        if end > 0:
            namespace = text[ns + len("namespace=") + 1 : end]
    for tag in ("<select", "<update", "<insert", "<delete", "<sql"):
        cursor = 0
        while True:
            start = text.find(tag, cursor)
            if start < 0:
                break
            closing_tag = "</" + tag[1:] + ">"
            end = text.find(closing_tag, start)
            if end < 0:
                break
            header_end = text.find(">", start, end)
            header = text[start:header_end] if header_end > 0 else ""
            statement_id = ""
            id_position = header.find('id="')
            if id_position >= 0:
                id_end = header.find('"', id_position + 4)
                statement_id = header[id_position + 4 : id_end] if id_end > 0 else ""
            body = text[start:end]
            for offset, inner in _scan_pairs(body, "${", "}"):
                root = inner.split(",", 1)[0].strip()
                if root.startswith("param.") or root.startswith("params."):
                    root = root.split(".", 1)[1]
                base = root.split(".", 1)[0].split("[", 1)[0]
                line, column = _line_col(text, start + offset)
                statements.append(
                    MapperStatement(namespace, statement_id, (base, root), line, column, relative)
                )
            cursor = end + len(closing_tag)
    return statements


def parse_properties(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw in text.split("\n")[:20000]:
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            continue
        separator = -1
        for index, char in enumerate(line[:400]):
            if char in "=:":
                separator = index
                break
        if separator <= 0:
            continue
        values[line[:separator].strip()] = line[separator + 1 :].strip()
    return values


def parse_yaml(text: str) -> Dict[str, str]:
    """YAML phẳng hóa theo thụt lề: đủ cho `a:\\n  b: giá trị` của cấu hình."""
    values: Dict[str, str] = {}
    stack: List[Tuple[int, str]] = []
    for raw in text.split("\n")[:20000]:
        if not raw.strip() or raw.lstrip().startswith(("#", "-", "---")):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        colon = line.find(":")
        if colon <= 0 or colon > 200:
            continue
        key = line[:colon].strip().strip("'\"")
        value = line[colon + 1 :].strip()
        while stack and stack[-1][0] >= indent:
            stack.pop()
        full = ".".join([item[1] for item in stack] + [key])
        if value and not value.startswith(("|", ">", "&", "*")):
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            values[full] = value
        elif value.startswith(("|", ">")):
            values[full] = ""
            stack.append((indent, key))
        else:
            stack.append((indent, key))
    return values


def strip_json_comments(text: str) -> str:
    """Bỏ chú thích và dấu phẩy thừa của JSONC ( tsconfig.json )."""
    out: List[str] = []
    index = 0
    limit = len(text)
    in_string = False
    while index < limit:
        char = text[index]
        if in_string:
            out.append(char)
            if char == "\\" and index + 1 < limit:
                out.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = limit if end < 0 else end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = limit if end < 0 else end + 2
            continue
        out.append(char)
        index += 1
    cleaned = "".join(out)
    # Dấu phẩy thừa trước } hoặc ].
    result: List[str] = []
    in_string = False
    for position, char in enumerate(cleaned):
        if char == '"' and (position == 0 or cleaned[position - 1] != "\\"):
            in_string = not in_string
        if char == "," and not in_string:
            ahead = position + 1
            while ahead < len(cleaned) and cleaned[ahead] in " \t\r\n":
                ahead += 1
            if ahead < len(cleaned) and cleaned[ahead] in "}]":
                continue
        result.append(char)
    return "".join(result)


def load_json(text: str) -> Optional[object]:
    try:
        return json.loads(strip_json_comments(text))
    except (ValueError, RecursionError):
        return None


def flatten_json(data: object, prefix: str = "", depth: int = 0, out: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    result: Dict[str, str] = {} if out is None else out
    if depth > 12 or len(result) > 20000:
        return result
    if isinstance(data, dict):
        for key, value in data.items():
            name = "%s.%s" % (prefix, key) if prefix else str(key)
            flatten_json(value, name, depth + 1, result)
    elif isinstance(data, str) and prefix:
        result[prefix] = data
    return result


def go_module(text: str) -> str:
    for raw in text.split("\n")[:50]:
        line = raw.strip()
        if line.startswith("module "):
            return line[len("module ") :].strip().strip('"')
    return ""
