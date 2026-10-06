"""Chỉ mục toàn dự án cho JavaScript/TypeScript, Java/JVM và Go.

Giữ "sự thật" tách ra từ từng tệp ( hàm, lớp, import, export, hằng số ) cộng
với những tệp không phải mã ( template, mapper SQL, cấu hình ), và trả lời một
câu hỏi duy nhất cho bộ phân tích: lời gọi `a.b.c(...)` ở vị trí này trỏ về
hàm nào, và summary của hàm đó là gì.

Phân giải theo hướng bảo toàn: tên không phân giải được thì bỏ, không đoán.
Chỉ một chỗ được phép trả về nhiều đích: kiểu là interface ( hay lớp trừu
tượng ) thì mọi lớp hiện thực đều có thể là đích thật của lời gọi -- đúng là
chuyện dependency injection làm trong mọi ứng dụng Spring hay NestJS.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from ...core.model import Category
from ...languages import GO, JAVA, JAVASCRIPT, TYPESCRIPT
from . import artifacts
from .model import Callee, ClassDef, FileFacts, FunctionDef, SinkHit, Summary
from .stream import TokenIndex

JS_FAMILY = frozenset({JAVASCRIPT, TYPESCRIPT})
SUPPORTED = frozenset({JAVASCRIPT, TYPESCRIPT, JAVA, GO})

_JS_EXTENSIONS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte")
_MAX_DEPTH = 8
MAX_FUNCTIONS = 60_000

# Chuỗi nguồn suy ra từ đối tượng request do framework truyền vào, theo kiểu.
_REQUEST_MEMBERS: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "express": (
        ("query", "tham số truy vấn HTTP"),
        ("body", "body của request HTTP"),
        ("params", "tham số đường dẫn HTTP"),
        ("headers", "header HTTP"),
        ("cookies", "cookie HTTP"),
        ("signedCookies", "cookie HTTP"),
        ("param", "tham số của request HTTP"),
        ("get", "header HTTP"),
        ("header", "header HTTP"),
        ("rawBody", "body của request HTTP"),
        ("file", "tệp tải lên"),
        ("files", "tệp tải lên"),
        ("hostname", "header HTTP"),
        ("originalUrl", "đường dẫn của request HTTP"),
        ("url", "đường dẫn của request HTTP"),
        ("path", "đường dẫn của request HTTP"),
        ("request.body", "body của request HTTP"),
        ("request.query", "tham số truy vấn HTTP"),
    ),
    "servlet": (
        ("getParameter", "tham số truy vấn HTTP"),
        ("getParameterValues", "tham số truy vấn HTTP"),
        ("getParameterMap", "tham số truy vấn HTTP"),
        ("getHeader", "header HTTP"),
        ("getHeaders", "header HTTP"),
        ("getQueryString", "query string HTTP"),
        ("getCookies", "cookie HTTP"),
        ("getInputStream", "body của request HTTP"),
        ("getReader", "body của request HTTP"),
        ("getRequestURI", "đường dẫn của request HTTP"),
        ("getPathInfo", "đường dẫn của request HTTP"),
        ("getPart", "tệp tải lên"),
    ),
    "webrequest": (
        ("getParameter", "tham số truy vấn HTTP"),
        ("getParameterValues", "tham số truy vấn HTTP"),
        ("getHeader", "header HTTP"),
    ),
    "nethttp": (
        ("URL.Query", "tham số truy vấn HTTP"),
        ("URL.RawQuery", "query string HTTP"),
        ("URL.Path", "đường dẫn của request HTTP"),
        ("FormValue", "trường form HTTP"),
        ("PostFormValue", "trường form HTTP"),
        ("Form", "trường form HTTP"),
        ("PostForm", "trường form HTTP"),
        ("Header.Get", "header HTTP"),
        ("Header", "header HTTP"),
        ("Body", "body của request HTTP"),
        ("Cookie", "cookie HTTP"),
        ("MultipartForm", "tệp tải lên"),
        ("FormFile", "tệp tải lên"),
        ("PathValue", "tham số đường dẫn HTTP"),
    ),
    "gin": (
        ("Query", "tham số truy vấn HTTP"),
        ("DefaultQuery", "tham số truy vấn HTTP"),
        ("GetQuery", "tham số truy vấn HTTP"),
        ("QueryArray", "tham số truy vấn HTTP"),
        ("QueryMap", "tham số truy vấn HTTP"),
        ("Param", "tham số đường dẫn HTTP"),
        ("PostForm", "trường form HTTP"),
        ("DefaultPostForm", "trường form HTTP"),
        ("GetPostForm", "trường form HTTP"),
        ("PostFormArray", "trường form HTTP"),
        ("GetHeader", "header HTTP"),
        ("Cookie", "cookie HTTP"),
        ("GetRawData", "body của request HTTP"),
        ("FormFile", "tệp tải lên"),
        ("Request.URL.Query", "tham số truy vấn HTTP"),
        ("Request.FormValue", "trường form HTTP"),
        ("Request.Body", "body của request HTTP"),
        ("Request.Header.Get", "header HTTP"),
    ),
    "echo": (
        ("QueryParam", "tham số truy vấn HTTP"),
        ("QueryParams", "tham số truy vấn HTTP"),
        ("QueryString", "query string HTTP"),
        ("Param", "tham số đường dẫn HTTP"),
        ("FormValue", "trường form HTTP"),
        ("FormParams", "trường form HTTP"),
        ("Cookie", "cookie HTTP"),
        ("Request.Header.Get", "header HTTP"),
        ("Request.Body", "body của request HTTP"),
    ),
    "fiber": (
        ("Query", "tham số truy vấn HTTP"),
        ("Params", "tham số đường dẫn HTTP"),
        ("FormValue", "trường form HTTP"),
        ("Get", "header HTTP"),
        ("Body", "body của request HTTP"),
        ("Cookies", "cookie HTTP"),
    ),
    "fasthttp": (
        ("QueryArgs", "tham số truy vấn HTTP"),
        ("PostArgs", "trường form HTTP"),
        ("FormValue", "trường form HTTP"),
        ("PostBody", "body của request HTTP"),
    ),
}


@dataclass
class QueueTaint:
    label: str
    path: str
    line: int


@dataclass
class ProjectStats:
    files: int = 0
    functions: int = 0
    summarized: int = 0
    with_effects: int = 0
    rounds: int = 0
    templates: int = 0
    mapper_statements: int = 0
    config_values: int = 0
    truncated: bool = False


class XProject:
    def __init__(self) -> None:
        self.facts: Dict[str, FileFacts] = {}
        self.functions: Dict[str, FunctionDef] = {}
        self.summaries: Dict[str, Summary] = {}
        self.stats = ProjectStats()
        # JS: đường dẫn không đuôi -> đường dẫn tệp thật.
        self._js_modules: Dict[str, str] = {}
        self._ts_paths: List[Tuple[str, str, Tuple[str, ...]]] = []
        self._ts_base_urls: List[str] = []
        self._packages: Dict[str, str] = {}
        # Java: tên đầy đủ -> lớp; gói -> danh sách tệp.
        self._java_classes: Dict[str, ClassDef] = {}
        self._java_packages: Dict[str, List[str]] = {}
        self._java_simple: Dict[str, List[ClassDef]] = {}
        # Go: thư mục -> tệp; tiền tố module -> thư mục gốc.
        self._go_dirs: Dict[str, List[str]] = {}
        self._go_modules: List[Tuple[str, str]] = []
        # Lớp hiện thực theo tên gọn của interface / lớp cha.
        self._implementers: Dict[Tuple[str, str], List[ClassDef]] = {}
        self._class_file: Dict[int, str] = {}
        self.templates: Dict[str, List[artifacts.TemplateInfo]] = {}
        # "autoescape" / "noEscape" -> nơi mã nguồn tắt escape của engine.
        self.escape_off: Dict[str, Tuple[str, int]] = {}
        self._enclosing: Dict[str, Optional[FunctionDef]] = {}
        self.mapper: Dict[Tuple[str, str], List[artifacts.MapperStatement]] = {}
        self.config: Dict[str, Tuple[str, str]] = {}
        self.data_files: Dict[str, Dict[str, str]] = {}
        self.node_config: Dict[str, str] = {}
        self.tainted_queues: Dict[str, QueueTaint] = {}
        self._extra_requests: Dict[str, List[Tuple[int, int, str, str]]] = {}
        self._extra_sources_cache: Dict[str, Dict[str, str]] = {}
        self._static_hits: Dict[str, Set[SinkHit]] = {}
        # Phép phân giải kiểu đang chạy dở: `x := x.Next()` không được tự gọi mình mãi.
        self._active: Set[Tuple[str, str, str, str]] = set()
        self._token_indexes: Dict[str, TokenIndex] = {}

    # ------------------------------------------------------------ building
    def add_file(self, facts: FileFacts) -> None:
        if self.stats.functions + len(facts.functions) > MAX_FUNCTIONS:
            self.stats.truncated = True
            return
        self.facts[facts.path] = facts
        self.stats.files += 1
        for function in facts.functions:
            if function.name:
                self.functions[function.key] = function
                self.stats.functions += 1
        for info in facts.classes.values():
            self._class_file[id(info)] = facts.path
        for setting, line in facts.template_settings:
            self.escape_off.setdefault(setting, (facts.path, line))
        if facts.language in JS_FAMILY:
            stem = _strip_js_extension(facts.path)
            self._js_modules.setdefault(stem, facts.path)
            if posixpath.basename(stem) == "index":
                self._js_modules.setdefault(posixpath.dirname(stem) or ".", facts.path)
        elif facts.language == JAVA:
            self._java_packages.setdefault(facts.package, []).append(facts.path)
            for info in facts.classes.values():
                self._java_classes.setdefault(info.qualified, info)
                self._java_simple.setdefault(info.name, []).append(info)
        elif facts.language == GO:
            self._go_dirs.setdefault(posixpath.dirname(facts.path), []).append(facts.path)

    def add_artifact(self, relative: str, text: str) -> None:
        lowered = relative.lower()
        name = posixpath.basename(lowered)
        if name == "go.mod":
            module = artifacts.go_module(text)
            if module:
                self._go_modules.append((module, posixpath.dirname(relative)))
            return
        if lowered.endswith(artifacts.TEMPLATE_SUFFIXES):
            info = artifacts.parse_template(relative, text)
            if info.outputs or info.escaped:
                self.stats.templates += 1
                for key in artifacts.template_keys(relative):
                    self.templates.setdefault(key, []).append(info)
            return
        if lowered.endswith(".xml"):
            for statement in artifacts.parse_mybatis(relative, text):
                self.mapper.setdefault((statement.namespace, statement.statement_id), []).append(statement)
                self.stats.mapper_statements += 1
            return
        if lowered.endswith(".properties"):
            for key, value in artifacts.parse_properties(text).items():
                self.config.setdefault(key, (value, relative))
            self.stats.config_values = len(self.config)
            return
        if lowered.endswith((".yml", ".yaml")):
            for key, value in artifacts.parse_yaml(text).items():
                self.config.setdefault(key, (value, relative))
            self.stats.config_values = len(self.config)
            return
        if lowered.endswith(".json"):
            data = artifacts.load_json(text)
            if data is None:
                return
            if name in ("tsconfig.json", "jsconfig.json") or (name.startswith("tsconfig") and name.endswith(".json")):
                self._tsconfig(relative, data)
                return
            if name == "package.json":
                self._package_json(relative, data)
                return
            flat = artifacts.flatten_json(data)
            self.data_files[relative] = flat
            parts = relative.replace("\\", "/").split("/")
            if len(parts) >= 2 and parts[-2] == "config":
                for key, value in flat.items():
                    self.node_config.setdefault(key, value)

    def _tsconfig(self, relative: str, data: object) -> None:
        if not isinstance(data, dict):
            return
        options = data.get("compilerOptions")
        if not isinstance(options, dict):
            return
        directory = posixpath.dirname(relative)
        base = options.get("baseUrl")
        base_dir = posixpath.normpath(posixpath.join(directory, base)) if isinstance(base, str) else directory
        if base_dir == ".":
            base_dir = ""
        if isinstance(base, str):
            self._ts_base_urls.append(base_dir)
        paths = options.get("paths")
        if isinstance(paths, dict):
            for alias, targets in paths.items():
                if isinstance(targets, list):
                    self._ts_paths.append(
                        (base_dir, str(alias), tuple(str(item) for item in targets if isinstance(item, str)))
                    )

    def _package_json(self, relative: str, data: object) -> None:
        if not isinstance(data, dict):
            return
        name = data.get("name")
        if isinstance(name, str) and name:
            directory = posixpath.dirname(relative)
            entry = ""
            for key in ("source", "module", "main", "types"):
                value = data.get(key)
                if isinstance(value, str):
                    entry = value
                    break
            self._packages[name] = posixpath.normpath(posixpath.join(directory, entry)) if entry else directory

    def finalize(self) -> None:
        """Nối những liên kết cần nhìn toàn dự án: lớp hiện thực, route, mapper."""
        for facts in self.facts.values():
            for info in facts.classes.values():
                for base in info.bases:
                    simple = base.rsplit(".", 1)[-1]
                    self._implementers.setdefault((_family(facts.language), simple), []).append(info)
        # Go: interface được thỏa mãn ngầm -- lớp nào có phương thức trùng tên
        # đều có thể đứng sau interface.
        for facts in self.facts.values():
            for path_route, anchor in facts.route_handlers:
                for target in self.resolve(facts.path, path_route, None, None):
                    function = target.function
                    if function.params and function.params[0] and function.language_ok:
                        pass
        self._wire_routes()
        self._mapper_summaries()

    def _wire_routes(self) -> None:
        for facts in self.facts.values():
            for chain, _ in facts.route_handlers:
                for function in self._targets(facts.path, chain, None, None):
                    if not function.params or not function.params[0]:
                        continue
                    kind = "express"
                    entry = (function.body_start, function.body_end, function.params[0], kind)
                    bucket = self._extra_requests.setdefault(function.path, [])
                    if entry not in bucket:
                        bucket.append(entry)

    def _mapper_summaries(self) -> None:
        for facts in self.facts.values():
            if facts.language != JAVA:
                continue
            for info in facts.classes.values():
                for name, methods in info.methods.items():
                    statements = self.mapper.get((info.qualified, name), [])
                    for function in methods:
                        hits = set()
                        for statement in statements:
                            position = _param_for(function, statement.roots)
                            if position is None:
                                continue
                            hits.add(
                                SinkHit(
                                    param=position,
                                    rule_id="FSB-SQL-001",
                                    category=Category.SQL,
                                    line=statement.line,
                                    column=statement.column,
                                    symbol="${%s}" % statement.roots[-1],
                                    description="một câu SQL nối chuỗi `${...}` trong mapper MyBatis",
                                    path=statement.path,
                                )
                            )
                        if hits:
                            self._merge_static(function, hits)
            for function, text, line, column in facts.inline_sql:
                hits = set()
                cursor = 0
                while True:
                    start = text.find("${", cursor)
                    if start < 0:
                        break
                    end = text.find("}", start, start + 200)
                    if end < 0:
                        break
                    root = text[start + 2 : end].split(",", 1)[0].strip()
                    base = root.split(".", 1)[0]
                    position = _param_for(function, (base, root))
                    if position is not None:
                        hits.add(
                            SinkHit(
                                param=position,
                                rule_id="FSB-SQL-001",
                                category=Category.SQL,
                                line=line,
                                column=column,
                                symbol="${%s}" % root,
                                description="một câu SQL nối chuỗi `${...}` trong chú thích MyBatis",
                                path=facts.path,
                            )
                        )
                    cursor = end + 1
                if hits:
                    self._merge_static(function, hits)

    def _merge_static(self, function: FunctionDef, hits: Iterable[SinkHit]) -> None:
        """Sink không đến từ thân hàm ( mapper XML, chú thích SQL ) mà vẫn thuộc về nó."""
        bucket = self._static_hits.setdefault(function.key, set())
        bucket.update(hits)
        current = self.summaries.get(function.key) or Summary()
        self.summaries[function.key] = Summary(
            sinks=frozenset(set(current.sinks) | bucket),
            returns=dict(current.returns),
            source=current.source,
            complete=current.complete,
        )

    def set_summary(self, function: FunctionDef, summary: Summary) -> bool:
        """Ghi summary mới; trả về True nếu nó khác bản cũ."""
        static = self._static_hits.get(function.key)
        if static:
            summary = Summary(
                sinks=frozenset(set(summary.sinks) | static),
                returns=summary.returns,
                source=summary.source,
                complete=summary.complete,
            )
        previous = self.summaries.get(function.key)
        if summary.same_as(previous):
            return False
        self.summaries[function.key] = summary
        return True

    # ------------------------------------------------------- extra sources
    def extra_sources(self, path: str) -> Dict[str, str]:
        cached = self._extra_sources_cache.get(path)
        if cached is not None:
            return cached
        facts = self.facts.get(path)
        result: Dict[str, str] = {}
        if facts is None:
            return result
        for _, _, name, kind in list(facts.request_objects) + self._extra_requests.get(path, []):
            for member, label in _REQUEST_MEMBERS.get(kind, ()):
                result.setdefault("%s.%s" % (name, member), label)
        for queue_name, _, job in facts.queue_consumers:
            taint = self.tainted_queues.get(queue_name)
            if taint is not None:
                result.setdefault(
                    "%s.data" % job,
                    "payload hàng đợi '%s' ( đẩy vào từ %s:%d, gốc là %s )"
                    % (queue_name, taint.path, taint.line, taint.label),
                )
        self._extra_sources_cache[path] = result
        return result

    def token_index(self, path: str, tokens) -> TokenIndex:
        """Chỉ mục vị trí token dùng chung cho mọi hàm của cùng một tệp."""
        cached = self._token_indexes.get(path)
        if cached is not None and cached.tokens is tokens:
            return cached
        index = TokenIndex(tokens)
        # Chỉ giữ tệp đang làm việc: summary đi lần lượt từng tệp.
        self._token_indexes = {path: index}
        return index

    def reset_source_cache(self) -> None:
        self._extra_sources_cache.clear()

    def seeded_parameters(self, path: str) -> Dict[str, Tuple[str, int]]:
        facts = self.facts.get(path)
        seeds: Dict[str, Tuple[str, int]] = {}
        if facts is None:
            return seeds
        for function in facts.functions:
            for name, label in zip(function.params, function.param_sources):
                if name and label:
                    seeds.setdefault(name, (label, function.line))
        return seeds

    # ------------------------------------------------------------ resolve
    def resolve(
        self,
        path: str,
        chain: str,
        function: Optional[FunctionDef],
        argument_count: Optional[int],
    ) -> List[Callee]:
        found: List[Callee] = []
        seen: Set[str] = set()
        for target in self._targets(path, chain, function, argument_count):
            if target.key in seen:
                continue
            seen.add(target.key)
            summary = self.summaries.get(target.key)
            if summary is None:
                continue
            found.append(Callee(function=target, summary=summary))
        return found

    def callable_exists(self, path: str, chain: str, function: Optional[FunctionDef], argument_count: Optional[int]) -> bool:
        return bool(self._targets(path, chain, function, argument_count))

    def _targets(
        self,
        path: str,
        chain: str,
        function: Optional[FunctionDef],
        argument_count: Optional[int],
    ) -> List[FunctionDef]:
        facts = self.facts.get(path)
        if facts is None or not chain:
            return []
        if facts.language in JS_FAMILY:
            targets = self._js_call(facts, chain, function)
        elif facts.language == JAVA:
            targets = self._java_call(facts, chain, function)
        elif facts.language == GO:
            targets = self._go_call(facts, chain, function)
        else:
            return []
        if argument_count is None or facts.language != JAVA:
            return targets
        exact = [item for item in targets if len(item.params) == argument_count or item.variadic]
        return exact or targets

    # ------------------------------------------------------------- JS
    def _js_resolve_module(self, from_path: str, spec: str) -> Optional[str]:
        candidates: List[str] = []
        if spec.startswith("."):
            candidates.append(posixpath.normpath(posixpath.join(posixpath.dirname(from_path), spec)))
        else:
            for base_dir, alias, targets in self._ts_paths:
                if alias.endswith("*"):
                    prefix = alias[:-1]
                    if spec.startswith(prefix):
                        rest = spec[len(prefix) :]
                        for target in targets:
                            candidates.append(
                                posixpath.normpath(posixpath.join(base_dir, target.replace("*", rest)))
                            )
                elif alias == spec:
                    for target in targets:
                        candidates.append(posixpath.normpath(posixpath.join(base_dir, target)))
            for base_dir in self._ts_base_urls:
                candidates.append(posixpath.normpath(posixpath.join(base_dir, spec)))
            # Gói trong workspace ( monorepo ): `@acme/db` -> packages/db.
            for name, entry in self._packages.items():
                if spec == name:
                    candidates.append(entry)
                elif spec.startswith(name + "/"):
                    candidates.append(posixpath.normpath(posixpath.join(posixpath.dirname(entry) if _has_js_ext(entry) else entry, spec[len(name) + 1 :])))
        for candidate in candidates:
            candidate = candidate.lstrip("./") if candidate.startswith("./") else candidate
            resolved = self._js_modules.get(_strip_js_extension(candidate))
            if resolved is not None:
                return resolved
            resolved = self._js_modules.get(candidate)
            if resolved is not None:
                return resolved
            # `./lib` -> `./lib/index.ts`; `./src` của gói -> `src/index.ts`.
            resolved = self._js_modules.get(posixpath.join(candidate, "index"))
            if resolved is not None:
                return resolved
            for source_dir in ("src", "lib"):
                resolved = self._js_modules.get(posixpath.join(candidate, source_dir, "index"))
                if resolved is not None:
                    return resolved
        return None

    def _js_data(self, from_path: str, spec: str) -> Optional[Dict[str, str]]:
        if not spec.startswith("."):
            return None
        target = posixpath.normpath(posixpath.join(posixpath.dirname(from_path), spec))
        return self.data_files.get(target)

    def _js_export(self, path: str, name: str, depth: int = 0) -> List[Tuple[str, str]]:
        """(tệp, tên cục bộ) mà tên xuất `name` của module `path` trỏ về."""
        if depth > _MAX_DEPTH:
            return []
        facts = self.facts.get(path)
        if facts is None:
            return []
        local = facts.exports.get(name)
        if local is not None:
            binding = facts.imports.get(local.split(".", 1)[0])
            if binding is not None and not _js_defines(facts, local.split(".", 1)[0]):
                target = self._js_resolve_module(path, binding.spec)
                if target is None:
                    return []
                rest = local.split(".", 1)[1] if "." in local else ""
                if binding.name == "*":
                    if not rest:
                        return [(target, "*")]
                    return self._js_export(target, rest.split(".", 1)[0], depth + 1)
                found = self._js_export(target, binding.name, depth + 1)
                if rest:
                    return [(p, "%s.%s" % (n, rest)) for p, n in found]
                return found
            return [(path, local)]
        found: List[Tuple[str, str]] = []
        for spec, remote, exported in facts.reexports:
            target = self._js_resolve_module(path, spec)
            if target is None:
                continue
            if exported == name:
                if remote == "*":
                    found.append((target, "*"))
                else:
                    found.extend(self._js_export(target, remote, depth + 1))
            elif remote == "*" and exported == "*" and name != "default":
                found.extend(self._js_export(target, name, depth + 1))
        if not found and name != "default" and "default" in facts.exports:
            # `module.exports = { run }` được import bằng `import { run }`.
            default_local = facts.exports["default"]
            if default_local in facts.objects and name in facts.objects[default_local]:
                return [(path, facts.objects[default_local][name])]
        return found

    def _js_call(self, facts: FileFacts, chain: str, function: Optional[FunctionDef]) -> List[FunctionDef]:
        parts = chain.split(".")
        if parts[0] == "this" and function is not None and function.owner:
            info = facts.classes.get(function.owner)
            if info is None:
                return []
            return self._js_member(facts.path, info, parts[1:], 0)
        if parts[0] == "this":
            return []
        if parts[0] == "super" and function is not None and function.owner:
            info = facts.classes.get(function.owner)
            if info is None:
                return []
            found: List[FunctionDef] = []
            for base in info.bases:
                for base_path, base_info in self._js_class(facts.path, base, 0):
                    found.extend(self._js_member(base_path, base_info, parts[1:], 1))
            return found
        # Biến cục bộ mang kiểu ( `const svc = new Service()` ).
        type_name = self._js_var_type(facts, parts[0], function)
        if type_name and len(parts) >= 2:
            found = []
            for class_path, info in self._js_class(facts.path, type_name, 0):
                found.extend(self._js_member(class_path, info, parts[1:], 0))
            if found:
                return found
        return self._js_name(facts.path, parts, 0)

    def _js_var_type(self, facts: FileFacts, name: str, function: Optional[FunctionDef]) -> str:
        # Đi từ hàm hiện tại ra các hàm bao ngoài: closure thấy biến của hàm
        # chứa nó ( `function Handler(db) { const dao = new Dao(db); this.x = () => dao.find() }` ).
        scope = function
        while scope is not None:
            env = facts.envs.get(scope.key, {})
            if name in env:
                return env[name]
            for param, param_type in zip(scope.params, scope.param_types):
                if param == name:
                    if param_type:
                        return param_type
                    return ""
            deferred = facts.deferred.get(scope.key, {}).get(name)
            if deferred:
                return self._js_return_type(facts, deferred, scope)
            scope = self.enclosing_function(facts, scope)
        if name in facts.module_types:
            return facts.module_types[name]
        deferred = facts.module_deferred.get(name)
        if deferred:
            return self._js_return_type(facts, deferred, None)
        return ""

    def enclosing_function(self, facts: FileFacts, function: FunctionDef) -> Optional[FunctionDef]:
        """Hàm nhỏ nhất trong cùng tệp có thân chứa trọn thân của `function`."""
        key = function.key
        if key in self._enclosing:
            return self._enclosing[key]
        best: Optional[FunctionDef] = None
        for candidate in facts.functions:
            if candidate is function or candidate.key == key or candidate.abstract:
                continue
            if candidate.body_start < function.body_start and function.body_end <= candidate.body_end:
                if best is None or candidate.body_start > best.body_start:
                    best = candidate
        self._enclosing[key] = best
        return best

    def _js_return_type(self, facts: FileFacts, chain: str, function: Optional[FunctionDef]) -> str:
        key = ("js", facts.path, chain, function.key if function is not None else "")
        if key in self._active:
            return ""
        self._active.add(key)
        try:
            return self._js_return_type_inner(facts, chain, function)
        finally:
            self._active.discard(key)

    def _js_return_type_inner(self, facts: FileFacts, chain: str, function: Optional[FunctionDef]) -> str:
        for target in self._js_call(facts, chain, function):
            if target.return_type:
                return target.return_type
            # Hàm factory `return new Service()`.
            target_facts = self.facts.get(target.path)
            if target_facts is not None:
                created = target_facts.envs.get(target.key, {}).get("<return>")
                if created:
                    return created
        return ""

    def _js_class(self, path: str, type_name: str, depth: int) -> List[Tuple[str, ClassDef]]:
        if depth > _MAX_DEPTH or not type_name:
            return []
        facts = self.facts.get(path)
        if facts is None:
            return []
        parts = type_name.split(".")
        head = parts[0]
        if len(parts) == 1 and head in facts.classes:
            return [(path, facts.classes[head])]
        binding = facts.imports.get(head)
        if binding is None:
            return []
        target = self._js_resolve_module(path, binding.spec)
        if target is None:
            return []
        if binding.name == "*":
            # `const Dao = require("./dao")` với `module.exports = Dao`.
            exported = parts[1] if len(parts) >= 2 else "default"
        else:
            exported = binding.name
        results: List[Tuple[str, ClassDef]] = []
        for class_path, local in self._js_export(target, exported, depth + 1):
            class_facts = self.facts.get(class_path)
            if class_facts is None:
                continue
            if local in class_facts.classes:
                results.append((class_path, class_facts.classes[local]))
            elif local in class_facts.imports:
                results.extend(self._js_class(class_path, local, depth + 1))
        return results

    def _js_member(self, path: str, info: ClassDef, parts: List[str], depth: int) -> List[FunctionDef]:
        if not parts or depth > _MAX_DEPTH:
            return []
        if len(parts) == 1:
            methods = self._js_methods(path, info, parts[0], depth)
            if methods:
                return methods
            # TypeScript interface: đi tới lớp hiện thực.
            found: List[FunctionDef] = []
            for implementer in self._implementers.get(("js", info.name), []):
                implementer_path = self._class_file.get(id(implementer), "")
                found.extend(implementer.methods.get(parts[0], []))
                if not implementer.methods.get(parts[0]) and implementer_path:
                    found.extend(self._js_methods(implementer_path, implementer, parts[0], depth + 1))
            return found
        field_type = info.fields.get(parts[0], "")
        if not field_type:
            return []
        if field_type.startswith("()"):
            facts = self.facts.get(path)
            if facts is None:
                return []
            field_type = self._js_return_type(facts, field_type[2:], None)
        results: List[FunctionDef] = []
        for class_path, field_info in self._js_class(path, field_type, depth + 1):
            results.extend(self._js_member(class_path, field_info, parts[1:], depth + 1))
        return results

    def _js_methods(self, path: str, info: ClassDef, name: str, depth: int) -> List[FunctionDef]:
        if depth > _MAX_DEPTH:
            return []
        methods = list(info.methods.get(name, []))
        if methods:
            return methods
        for base in info.bases:
            for base_path, base_info in self._js_class(path, base, depth + 1):
                methods.extend(self._js_methods(base_path, base_info, name, depth + 1))
        return methods

    def _js_name(self, path: str, parts: List[str], depth: int) -> List[FunctionDef]:
        """Phân giải `a`, `a.b`, `a.b.c` theo tên trong tệp `path`."""
        if depth > _MAX_DEPTH:
            return []
        facts = self.facts.get(path)
        if facts is None:
            return []
        head = parts[0]
        rest = parts[1:]
        # Hàm cấp module trong chính tệp.
        if not rest:
            local = [f for f in facts.functions if f.name == head and not f.owner]
            if local:
                return local
        if rest:
            qualified = ".".join(parts)
            local = [f for f in facts.functions if f.qualname == qualified]
            if local:
                return local
            if head in facts.classes:
                return self._js_member(path, facts.classes[head], rest, depth)
            if head in facts.objects:
                member = facts.objects[head].get(rest[0])
                if member is not None:
                    return self._js_name(path, member.split(".") + rest[1:], depth + 1)
        binding = facts.imports.get(head)
        if binding is not None and not _js_defines(facts, head):
            target = self._js_resolve_module(path, binding.spec)
            if target is None:
                return []
            if binding.name == "*":
                if not rest:
                    return self._js_resolved_export(target, "default", [], depth)
                return self._js_resolved_export(target, rest[0], rest[1:], depth)
            return self._js_resolved_export(target, binding.name, rest, depth)
        return []

    def _js_resolved_export(self, module: str, name: str, rest: List[str], depth: int) -> List[FunctionDef]:
        results: List[FunctionDef] = []
        for target_path, local in self._js_export(module, name, depth + 1):
            if local == "*":
                if rest:
                    results.extend(self._js_resolved_export(target_path, rest[0], rest[1:], depth + 1))
                continue
            target_facts = self.facts.get(target_path)
            if target_facts is None:
                continue
            if local == "default" and "default" in target_facts.module_types and rest:
                for class_path, info in self._js_class(target_path, target_facts.module_types["default"], depth + 1):
                    results.extend(self._js_member(class_path, info, rest, depth + 1))
                continue
            if local in target_facts.module_types and rest:
                for class_path, info in self._js_class(target_path, target_facts.module_types[local], depth + 1):
                    results.extend(self._js_member(class_path, info, rest, depth + 1))
                continue
            results.extend(self._js_name(target_path, local.split(".") + rest, depth + 1))
        return results

    def js_dispatch(self, path: str, table: str) -> List[FunctionDef]:
        facts = self.facts.get(path)
        if facts is None:
            return []
        results: List[FunctionDef] = []
        for member in facts.dispatch_tables.get(table, ()):
            results.extend(self._js_name(path, member.split("."), 0))
        return results

    # ----------------------------------------------------------- Java
    def _java_class(self, facts: FileFacts, name: str) -> List[ClassDef]:
        if not name:
            return []
        simple = name.rsplit(".", 1)[-1]
        if "." in name and name in self._java_classes:
            return [self._java_classes[name]]
        if simple in facts.classes:
            return [facts.classes[simple]]
        binding = facts.imports.get(simple)
        if binding is not None:
            info = self._java_classes.get(binding.spec)
            return [info] if info is not None else []
        same_package = "%s.%s" % (facts.package, simple) if facts.package else simple
        if same_package in self._java_classes:
            return [self._java_classes[same_package]]
        for package in facts.wildcard_imports:
            candidate = self._java_classes.get("%s.%s" % (package, simple))
            if candidate is not None:
                return [candidate]
        return []

    def _java_facts_of(self, info: ClassDef) -> Optional[FileFacts]:
        return self.facts.get(self._class_file.get(id(info), info.path))

    def _java_methods(self, info: ClassDef, name: str, depth: int = 0) -> List[FunctionDef]:
        if depth > _MAX_DEPTH:
            return []
        own = list(info.methods.get(name, []))
        concrete = [item for item in own if not item.abstract]
        abstract = [item for item in own if item.abstract]
        results: List[FunctionDef] = list(concrete) + abstract
        if not concrete:
            facts = self._java_facts_of(info)
            if facts is not None:
                for base in info.bases:
                    for base_info in self._java_class(facts, base):
                        results.extend(self._java_methods(base_info, name, depth + 1))
        # Interface / lớp trừu tượng: lớp hiện thực có thể là đích thật.
        if info.is_interface or abstract or not own:
            for implementer in self._implementers.get(("jvm", info.name), []):
                implementer_facts = self._java_facts_of(implementer)
                if implementer_facts is None:
                    continue
                resolved = [base for base in implementer.bases if any(c is info for c in self._java_class(implementer_facts, base))]
                if not resolved:
                    continue
                results.extend(item for item in implementer.methods.get(name, []) if not item.abstract)
        return results

    def _java_type_of(self, facts: FileFacts, name: str, function: Optional[FunctionDef], current: Optional[ClassDef]) -> str:
        if function is not None:
            env = facts.envs.get(function.key, {})
            if name in env:
                return env[name]
            deferred = facts.deferred.get(function.key, {}).get(name)
            key = ("jvm", facts.path, deferred, function.key)
            if deferred and key not in self._active:
                self._active.add(key)
                try:
                    for target in self._java_call(facts, deferred, function):
                        if target.return_type:
                            return target.return_type
                finally:
                    self._active.discard(key)
        if current is not None:
            info: Optional[ClassDef] = current
            depth = 0
            while info is not None and depth < _MAX_DEPTH:
                if name in info.fields:
                    return info.fields[name]
                owner_facts = self._java_facts_of(info)
                next_info = None
                if owner_facts is not None:
                    for base in info.bases:
                        candidates = self._java_class(owner_facts, base)
                        if candidates:
                            next_info = candidates[0]
                            break
                info = next_info
                depth += 1
        return ""

    def _java_call(self, facts: FileFacts, chain: str, function: Optional[FunctionDef]) -> List[FunctionDef]:
        parts = chain.split(".")
        current = facts.classes.get(function.owner) if function is not None and function.owner else None
        if parts[0] == "this":
            parts = parts[1:]
            if not parts:
                return []
            if len(parts) == 1:
                return self._java_methods(current, parts[0]) if current else []
        if parts[0] == "super" and current is not None:
            results: List[FunctionDef] = []
            for base in current.bases:
                for info in self._java_class(facts, base):
                    results.extend(self._java_methods(info, parts[-1]))
            return results
        if len(parts) == 1:
            name = parts[0]
            if current is not None:
                methods = self._java_methods(current, name)
                if methods:
                    return methods
            static = facts.static_imports.get(name)
            if static is not None:
                info = self._java_classes.get(static[0])
                if info is not None:
                    return self._java_methods(info, static[1])
            if facts.path.endswith((".kt", ".kts")):
                return [f for f in facts.functions if f.name == name and not f.owner]
            return []
        # Đầu chuỗi: biến cục bộ / trường mang kiểu, hoặc tên lớp ( gọi tĩnh ).
        type_name = self._java_type_of(facts, parts[0], function, current)
        classes: List[ClassDef] = []
        context_facts = facts
        if type_name:
            classes = self._java_class(facts, type_name)
        elif parts[0][:1].isupper():
            classes = self._java_class(facts, parts[0])
        for middle in parts[1:-1]:
            next_classes: List[ClassDef] = []
            for info in classes:
                field_type = info.fields.get(middle, "")
                owner_facts = self._java_facts_of(info) or context_facts
                if field_type:
                    next_classes.extend(self._java_class(owner_facts, field_type))
            classes = next_classes
        results = []
        for info in classes:
            results.extend(self._java_methods(info, parts[-1]))
        return results

    def java_constant(self, facts: FileFacts, chain: str, function: Optional[FunctionDef]) -> Optional[Tuple[str, str]]:
        parts = chain.split(".")
        if parts[0] == "this":
            parts = parts[1:]
        if not parts:
            return None
        current = facts.classes.get(function.owner) if function is not None and function.owner else None
        if len(parts) == 1 and current is not None:
            name = parts[0]
            if name in current.constants:
                return current.constants[name], facts.path
            key = current.config_fields.get(name)
            if key is not None and key in self.config:
                return self.config[key]
            return None
        if len(parts) == 2:
            for info in self._java_class(facts, parts[0]):
                if parts[1] in info.constants:
                    return info.constants[parts[1]], self._class_file.get(id(info), info.path)
                key = info.config_fields.get(parts[1])
                if key is not None and key in self.config:
                    return self.config[key]
        return None

    # -------------------------------------------------------------- Go
    def _go_dir_for_import(self, spec: str) -> Optional[str]:
        for module, root in sorted(self._go_modules, key=lambda item: -len(item[0])):
            if spec == module:
                return root or "."
            if spec.startswith(module + "/"):
                rest = spec[len(module) + 1 :]
                return posixpath.normpath(posixpath.join(root, rest)) if root else rest
        # Không có go.mod: thử khớp hậu tố đường dẫn với một thư mục có mã Go.
        candidates = [directory for directory in self._go_dirs if spec.endswith("/" + directory) or spec == directory]
        if len(candidates) == 1:
            return candidates[0]
        return None

    def _go_package_files(self, directory: str) -> List[FileFacts]:
        return [self.facts[path] for path in self._go_dirs.get(directory if directory != "." else "", []) if path in self.facts]

    def _go_type(self, facts: FileFacts, type_name: str) -> List[ClassDef]:
        if not type_name:
            return []
        directory = posixpath.dirname(facts.path)
        if "." in type_name:
            alias, _, simple = type_name.partition(".")
            binding = facts.imports.get(alias)
            if binding is None:
                return []
            directory_found = self._go_dir_for_import(binding.spec)
            if directory_found is None:
                return []
            directory = "" if directory_found == "." else directory_found
        else:
            simple = type_name
        results = []
        for package_facts in self._go_package_files(directory):
            if simple in package_facts.classes:
                results.append(package_facts.classes[simple])
        return results

    def _go_methods(self, info: ClassDef, name: str, depth: int = 0) -> List[FunctionDef]:
        if depth > _MAX_DEPTH:
            return []
        # Phương thức của kiểu nằm rải rác nhiều tệp trong cùng gói.
        info_path = self._class_file.get(id(info), info.path)
        directory = posixpath.dirname(info_path)
        methods: List[FunctionDef] = []
        for package_facts in self._go_package_files(directory):
            other = package_facts.classes.get(info.name)
            if other is not None:
                methods.extend(item for item in other.methods.get(name, []) if not item.abstract)
        if methods:
            return methods
        facts = self.facts.get(info_path)
        if facts is not None:
            for base in info.bases:
                for base_info in self._go_type(facts, base):
                    methods.extend(self._go_methods(base_info, name, depth + 1))
        if info.is_interface and name in info.methods:
            # Interface Go được thỏa mãn ngầm: mọi kiểu có phương thức trùng
            # tên và cùng số tham số đều là đích có thể.
            wanted = info.methods[name][0]
            for other_facts in self.facts.values():
                if other_facts.language != GO:
                    continue
                for other in other_facts.classes.values():
                    if other.is_interface:
                        continue
                    for candidate in other.methods.get(name, []):
                        if len(candidate.params) == len(wanted.params) and not candidate.abstract:
                            methods.append(candidate)
        return methods

    def _go_var_type(self, facts: FileFacts, name: str, function: Optional[FunctionDef]) -> List[ClassDef]:
        if function is None:
            return []
        env = facts.envs.get(function.key, {})
        if name in env:
            return self._go_type(facts, env[name])
        deferred = facts.deferred.get(function.key, {}).get(name)
        key = ("go", facts.path, deferred or "", function.key)
        if deferred and key not in self._active:
            self._active.add(key)
            try:
                results: List[ClassDef] = []
                for target in self._go_call(facts, deferred, function):
                    if target.return_type:
                        target_facts = self.facts.get(target.path)
                        if target_facts is not None:
                            results.extend(self._go_type(target_facts, target.return_type))
                return results
            finally:
                self._active.discard(key)
        return []

    def _go_call(self, facts: FileFacts, chain: str, function: Optional[FunctionDef]) -> List[FunctionDef]:
        parts = chain.split(".")
        directory = posixpath.dirname(facts.path)
        if len(parts) == 1:
            results = []
            for package_facts in self._go_package_files(directory):
                results.extend(f for f in package_facts.functions if f.name == parts[0] and not f.owner)
            return results
        classes = self._go_var_type(facts, parts[0], function)
        if not classes:
            binding = facts.imports.get(parts[0])
            if binding is not None:
                package_dir = self._go_dir_for_import(binding.spec)
                if package_dir is None:
                    return []
                package_dir = "" if package_dir == "." else package_dir
                if len(parts) == 2:
                    results = []
                    for package_facts in self._go_package_files(package_dir):
                        results.extend(f for f in package_facts.functions if f.name == parts[1] and not f.owner)
                    return results
                return []
        for middle in parts[1:-1]:
            next_classes: List[ClassDef] = []
            for info in classes:
                field_type = info.fields.get(middle, "")
                owner_facts = self.facts.get(self._class_file.get(id(info), info.path))
                if field_type and owner_facts is not None:
                    next_classes.extend(self._go_type(owner_facts, field_type))
            classes = next_classes
        results = []
        for info in classes:
            results.extend(self._go_methods(info, parts[-1]))
        return results

    def go_constant(self, facts: FileFacts, chain: str) -> Optional[Tuple[str, str]]:
        parts = chain.split(".")
        directory = posixpath.dirname(facts.path)
        if len(parts) == 1:
            for package_facts in self._go_package_files(directory):
                if parts[0] in package_facts.constants:
                    return package_facts.constants[parts[0]], package_facts.path
            return None
        if len(parts) == 2:
            binding = facts.imports.get(parts[0])
            if binding is None:
                return None
            package_dir = self._go_dir_for_import(binding.spec)
            if package_dir is None:
                return None
            package_dir = "" if package_dir == "." else package_dir
            for package_facts in self._go_package_files(package_dir):
                if parts[1] in package_facts.constants:
                    return package_facts.constants[parts[1]], package_facts.path
        return None

    # ---------------------------------------------------------- constants
    def constant(self, path: str, chain: str, function: Optional[FunctionDef]) -> Optional[Tuple[str, str]]:
        """Giá trị chuỗi hằng của `chain` nếu nó phân giải được, kèm tệp gốc."""
        facts = self.facts.get(path)
        if facts is None:
            return None
        if facts.language == JAVA:
            return self.java_constant(facts, chain, function)
        if facts.language == GO:
            return self.go_constant(facts, chain)
        return self._js_constant(facts, chain, 0)

    def _js_constant(self, facts: FileFacts, chain: str, depth: int) -> Optional[Tuple[str, str]]:
        if depth > _MAX_DEPTH:
            return None
        if chain in facts.constants:
            return facts.constants[chain], facts.path
        parts = chain.split(".")
        head = parts[0]
        if head in facts.data_imports and len(parts) >= 2:
            data = self._js_data(facts.path, facts.data_imports[head])
            if data is not None:
                key = ".".join(parts[1:])
                if key in data:
                    return data[key], posixpath.normpath(posixpath.join(posixpath.dirname(facts.path), facts.data_imports[head]))
            return None
        binding = facts.imports.get(head)
        if binding is None:
            return None
        if binding.spec.endswith(".json"):
            data = self._js_data(facts.path, binding.spec)
            if data is not None:
                key = ".".join(parts[1:]) if binding.name in ("*", "default") else ".".join([binding.name] + parts[1:])
                if key in data:
                    return data[key], binding.spec
            return None
        target = self._js_resolve_module(facts.path, binding.spec)
        if target is None:
            return None
        if binding.name == "*":
            if len(parts) < 2:
                return None
            exported, rest = parts[1], parts[2:]
        else:
            exported, rest = binding.name, parts[1:]
        for target_path, local in self._js_export(target, exported, depth + 1):
            target_facts = self.facts.get(target_path)
            if target_facts is None or local == "*":
                continue
            found = self._js_constant(target_facts, ".".join([local] + rest), depth + 1)
            if found is not None:
                return found
        return None

    def config_value(self, key: str) -> Optional[Tuple[str, str]]:
        if key in self.node_config:
            return self.node_config[key], "config"
        normalized = key.replace(":", ".")
        if normalized in self.node_config:
            return self.node_config[normalized], "config"
        if normalized in self.config:
            return self.config[normalized]
        return None

    # ------------------------------------------------------------ templates
    def template_outputs(self, template: artifacts.TemplateInfo) -> List[artifacts.RawOutput]:
        """Chỗ in thô của template, tính cả `{{ x }}` khi engine tắt escape."""
        if not template.escaped:
            return template.outputs
        used = None
        if template.family in ("jinja", "either") and "autoescape" in self.escape_off:
            used = "autoescape"
        elif template.family in ("mustache", "either") and "noEscape" in self.escape_off:
            used = "noEscape"
        if used is None:
            return template.outputs
        path, line = self.escape_off[used]
        label = "autoescape: false" if used == "autoescape" else "noEscape: true"
        syntax = "{{ }} khi engine đặt %s ( %s:%d )" % (label, path, line)
        extra = [artifacts.RawOutput(o.root, o.line, o.column, syntax) for o in template.escaped]
        return list(template.outputs) + extra

    def templates_for(self, name: str) -> List[artifacts.TemplateInfo]:
        key = name.strip().lstrip("/").replace("\\", "/")
        found = self.templates.get(key, [])
        if found:
            return found
        for prefix in ("views/", "templates/", "src/main/resources/templates/"):
            found = self.templates.get(prefix + key, [])
            if found:
                return found
        return []


def _family(language: str) -> str:
    if language in JS_FAMILY:
        return "js"
    if language == JAVA:
        return "jvm"
    return language


def _strip_js_extension(path: str) -> str:
    for extension in (".d.ts",) + _JS_EXTENSIONS:
        if path.endswith(extension):
            return path[: -len(extension)]
    return path


def _has_js_ext(path: str) -> bool:
    return path.endswith(_JS_EXTENSIONS)


def _js_defines(facts: FileFacts, name: str) -> bool:
    """Tệp tự định nghĩa `name` ( hàm, lớp, object ) -- che mất import cùng tên."""
    if name in facts.classes or name in facts.objects:
        return True
    return any(f.name == name and not f.owner for f in facts.functions)


def _param_for(function: FunctionDef, roots: Tuple[str, ...]) -> Optional[int]:
    base = roots[0]
    for index, alias in enumerate(function.param_aliases):
        if alias and alias == base:
            return index
    for index, name in enumerate(function.params):
        if name == base:
            return index
    if len(function.params) == 1:
        # MyBatis cho tham số duy nhất được gọi bằng bất kỳ tên nào, kể cả
        # truy cập trường của đối tượng ( `${name}` với tham số `User u` ).
        return 0
    return None


def cleared_union(values: Iterable[FrozenSet[Category]]) -> FrozenSet[Category]:
    result: FrozenSet[Category] = frozenset()
    for value in values:
        result = result | value
    return result
