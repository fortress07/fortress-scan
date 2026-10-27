from __future__ import annotations

import io
import os
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Set, Tuple

from ..languages import (
    PYTHON,
    detect_language,
    is_scannable_name,
    language_from_name,
    language_from_relative,
)
from ..analysis.xfile import artifacts
from ..security import paths as safe_paths
from .config import Config
from .ignore import IgnoreSet, MatchBudget
from .model import ScanError

IGNORE_FILENAMES: Tuple[str, ...] = (".fortress-scanignore",)
VCS_IGNORE_FILENAMES: Tuple[str, ...] = (".gitignore",)

_BINARY_PROBE_BYTES = 8192
_MAX_STRAY_NULL_BYTES = 4


class FileChangedDuringScan(Exception):
    """Tệp mở ra không còn là tệp đã được liệt kê lúc duyệt cây."""


@dataclass(frozen=True)
class DiscoveredFile:
    path: Path
    relative: str
    language: str
    size: int
    identity: Optional[Tuple[int, int]] = None


class Discovery:
    def __init__(self, root: Path, config: Config) -> None:
        self._root = root
        self._config = config
        self._excluded = frozenset(config.excluded_directories)
        # Một túi hạn mức duy nhất cho cả lượt quét. Chi phí so khớp là
        # tokens x độ_dài_đường_dẫn x số_entry, mà chỉ thừa số đầu có trần, nên
        # trần thật phải đặt ở chỗ cộng dồn được cả ba.
        self._match_budget = MatchBudget()
        self._explicit = IgnoreSet.from_lines(
            config.exclude_patterns, budget=self._match_budget
        )
        self._include = IgnoreSet.from_lines(
            config.include_patterns, budget=self._match_budget
        )
        self._visited_directories: Set[Tuple[int, int]] = set()
        self._visited_files: Set[Tuple[int, int]] = set()
        self.errors: List[ScanError] = []
        self.skipped = 0
        self.skipped_links = 0
        # Tệp ignore nằm TRONG cây được quét, tức là do người viết repo đặt --
        # cùng loại dữ liệu không tin cậy với .fortress-scan.json. Không đếm thì
        # một báo cáo "sạch" do chúng tạo ra không nói được vì sao mình sạch.
        self.ignored_files = 0
        self.ignored_directories = 0
        # Danh sách loại trừ mặc định là quyết định của công cụ, không phải của
        # repo, nên nó đi vào thống kê chứ không thành CẢNH BÁO.
        self.excluded_directories_hit = 0
        self.artifacts: List[DiscoveredFile] = []

    def _consider_artifact(self, path: Path, relative: str, name: str) -> None:
        """Tệp không phải mã mà luồng dữ liệu đi qua ( template, mapper, cấu hình ).

        Không vào danh sách phân tích và không vào thống kê ngôn ngữ: nó chỉ là
        dữ liệu cho phân tích xuyên file đọc khi cần.
        """
        if len(self.artifacts) >= artifacts.MAX_ARTIFACTS or not artifacts.is_artifact_name(name):
            return
        size = _artifact_size(path)
        if size is None:
            return
        self.artifacts.append(DiscoveredFile(path=path, relative=relative, language="artifact", size=size))

    @property
    def ignore_budget_exhausted(self) -> bool:
        """Hạn mức so khớp đã cạn nên quy tắc ignore ngừng có hiệu lực."""
        return self._match_budget.exhausted

    def walk(self) -> Iterator[DiscoveredFile]:
        if self._root.is_file():
            candidate = self._consider(self._root, self._root.name)
            if candidate is not None:
                yield candidate
            return
        base_ignore = self._load_ignore_files(self._root)
        yielded = 0
        total_bytes = 0
        for discovered in self._walk_directory(self._root, base_ignore, 0):
            if yielded >= self._config.max_files:
                self.errors.append(
                    ScanError(
                        path=".",
                        reason="file-limit-reached",
                        detail="dừng sau %d tệp" % self._config.max_files,
                    )
                )
                return
            total_bytes += discovered.size
            if total_bytes > self._config.max_total_bytes:
                self.errors.append(
                    ScanError(
                        path=".",
                        reason="byte-limit-reached",
                        detail="dừng sau %d byte" % self._config.max_total_bytes,
                    )
                )
                return
            yielded += 1
            yield discovered

    def _load_ignore_files(self, directory: Path) -> IgnoreSet:
        ignore = self._explicit
        names: List[str] = []
        if self._config.respect_ignore_files:
            names.extend(IGNORE_FILENAMES)
        if self._config.respect_vcs_ignore:
            names.extend(VCS_IGNORE_FILENAMES)
        for name in names:
            candidate = directory / name
            if candidate.is_file() and not safe_paths.is_link_like(candidate):
                loaded = IgnoreSet.from_file(candidate, budget=self._match_budget)
                if loaded.overflowed:
                    self.errors.append(
                        ScanError(
                            path=safe_paths.relative_display(self._root, candidate),
                            reason="ignore-file-too-complex",
                            detail=(
                                "vượt hạn mức mẫu nên toàn bộ quy tắc trong tệp này bị bỏ; "
                                "không tệp nào bị ẩn khỏi lượt quét"
                            ),
                        )
                    )
                ignore = ignore.merged(loaded)
        return ignore

    def _walk_directory(
        self, directory: Path, inherited: IgnoreSet, depth: int
    ) -> Iterator[DiscoveredFile]:
        if depth > 64:
            self.errors.append(
                ScanError(
                    path=safe_paths.relative_display(self._root, directory),
                    reason="depth-limit",
                    detail="thư mục lồng nhau vượt quá 64 cấp",
                )
            )
            return
        try:
            key = self._directory_key(directory)
        except OSError:
            return
        if key is not None:
            if key in self._visited_directories:
                return
            self._visited_directories.add(key)

        ignore = inherited if depth == 0 else inherited.merged(self._load_ignore_files(directory))

        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            self.errors.append(
                ScanError(
                    path=safe_paths.relative_display(self._root, directory),
                    reason="unreadable-directory",
                    detail=exc.strerror or "",
                )
            )
            return

        subdirectories: List[Path] = []
        for entry in entries:
            entry_path = Path(entry.path)
            relative = safe_paths.relative_display(self._root, entry_path)

            target = self._resolve_entry(entry, entry_path, relative)
            if target is None:
                continue
            is_directory = self._entry_is_directory(entry, entry_path, target)
            if is_directory is None:
                continue

            if is_directory:
                if entry.name in self._excluded:
                    self.excluded_directories_hit += 1
                    continue
                if ignore.matches(relative, True):
                    if not self._chosen_by_user(relative, True):
                        self.ignored_directories += 1
                    continue
                subdirectories.append(target)
                continue

            if ignore.matches(relative, False):
                if not self._chosen_by_user(relative, False) and language_from_name(
                    entry_path.name
                ) is not None:
                    self.ignored_files += 1
                continue
            if self._include and not self._include.matches(relative, False):
                continue
            candidate = self._consider(target, relative, entry_path.name)
            if candidate is not None:
                yield candidate

        for subdirectory in subdirectories:
            for discovered in self._walk_directory(subdirectory, ignore, depth + 1):
                yield discovered

    def _chosen_by_user(self, relative: str, is_directory: bool) -> bool:
        """Đường dẫn này bị loại vì --exclude / khoá `exclude` chứ không phải vì
        một tệp ignore trong cây.

        Người dùng tự gõ --exclude thì không cần ai cảnh báo lại họ, còn khoá
        `exclude` trong .fortress-scan.json đã có cảnh báo riêng rồi. Kiểm sau
        khi đã biết đường dẫn bị loại nên phép so thêm này chỉ chạy cho số ít
        entry, và cách gộp quy tắc ở trên giữ nguyên không đổi.
        """
        return bool(self._explicit) and self._explicit.matches(relative, is_directory)

    def _resolve_entry(
        self, entry: "os.DirEntry[str]", entry_path: Path, relative: str
    ) -> Optional[Path]:
        """Tệp thật mà entry này trỏ tới, hoặc None nếu phải bỏ qua nó."""
        if not self._is_link(entry, entry_path):
            return entry_path
        if not self._config.follow_symlinks:
            self.skipped += 1
            self.skipped_links += 1
            return None
        resolved = safe_paths.safe_resolve(self._root, entry_path)
        if resolved is None:
            self.skipped += 1
            self.skipped_links += 1
            self.errors.append(
                ScanError(
                    path=relative,
                    reason="link-escapes-root",
                    detail="liên kết trỏ ra ngoài thư mục đang quét",
                )
            )
            return None
        return resolved

    def _entry_is_directory(
        self, entry: "os.DirEntry[str]", entry_path: Path, target: Path
    ) -> Optional[bool]:
        """Hỏi về ĐÍCH, không hỏi về chính liên kết; None nghĩa là không đọc được.

        `is_dir(follow_symlinks=False)` soi lstat của chính liên kết, nên mọi
        symlink đều trả lời "không phải thư mục" -- kể cả khi nó trỏ tới một
        thư mục nằm ngay trong phạm vi quét. Lấy câu trả lời đó để quyết định
        có đi theo liên kết hay không thì cả cây con phía sau nó biến mất khỏi
        lượt quét, và biến mất trong im lặng.
        """
        try:
            if target is entry_path:
                return entry.is_dir(follow_symlinks=False)
            return target.is_dir()
        except OSError:
            return None

    def _is_link(self, entry: "os.DirEntry[str]", entry_path: Path) -> bool:
        try:
            if entry.is_symlink():
                return True
        except OSError:
            return True
        junction_check = getattr(entry, "is_junction", None)
        if junction_check is not None:
            try:
                if junction_check():
                    return True
            except OSError:
                return True
        return safe_paths.is_link_like(entry_path)

    def _directory_key(self, directory: Path) -> Optional[Tuple[int, int]]:
        return _identity(os.stat(directory))

    def _consider(
        self, path: Path, relative: str, name: Optional[str] = None
    ) -> Optional[DiscoveredFile]:
        label = name or path.name
        # Vị trí nói trước tên: một tệp trong .github/workflows là mã CI dù
        # phần mở rộng của nó chỉ là .yml, và nếu hỏi theo tên trước thì
        # không bộ nhận dạng nào trả lời được.
        language = language_from_relative(relative)
        if language is None:
            if not is_scannable_name(label):
                return None
            language = detect_language(path, label)
        if language is None:
            self._consider_artifact(path, relative, label)
            return None
        if not safe_paths.is_regular_file(path):
            self.skipped += 1
            return None
        try:
            status = path.stat()
        except OSError:
            self.skipped += 1
            return None
        # Một cây có liên kết thì cùng một tệp tới đây nhiều lần dưới nhiều tên
        # (workspace kiểu pnpm là cả một rừng như vậy). Quét lại nó không tìm
        # thêm được gì, chỉ nhân bản phát hiện ra nhiều đường dẫn.
        identity = _identity(status)
        if identity is not None:
            if identity in self._visited_files:
                return None
            self._visited_files.add(identity)
        size = status.st_size
        if size == 0:
            return None
        if size > self._config.max_file_bytes:
            self.skipped += 1
            self.errors.append(
                ScanError(
                    path=relative,
                    reason="file-too-large",
                    detail="%d byte vượt giới hạn %d byte"
                    % (size, self._config.max_file_bytes),
                )
            )
            return None
        if _looks_binary(path):
            self.skipped += 1
            # Bỏ qua thì được, nhưng bỏ qua trong im lặng thì không: tệp này
            # mang phần mở rộng của một ngôn ngữ được hỗ trợ, nên người đọc
            # báo cáo phải biết là nó chưa từng được soi.
            self.errors.append(
                ScanError(
                    path=relative,
                    reason="binary-skipped",
                    detail="tệp %s chứa dữ liệu nhị phân nên không được phân tích" % language,
                )
            )
            return None
        return DiscoveredFile(
            path=path,
            relative=relative,
            language=language,
            size=size,
            identity=identity,
        )


def _artifact_size(path: Path) -> Optional[int]:
    if not safe_paths.is_regular_file(path):
        return None
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size == 0 or size > artifacts.MAX_ARTIFACT_BYTES:
        return None
    return size


def _identity(status: os.stat_result) -> Optional[Tuple[int, int]]:
    """Danh tính (thiết bị, inode) của một entry, hoặc None nếu không tin được.

    Vài hệ thống tệp trả về 0 cho những trường này -- share mạng, FAT, một số
    kiểu mount trong container. Coi 0 là một danh tính hợp lệ thì MỌI entry
    trùng nhau: thư mục thứ hai trở đi bị coi là đã duyệt rồi, và cả lượt quét
    dừng lại sau thư mục đầu tiên mà không in ra một dòng lỗi nào.

    Không biết chắc thì đừng gộp. Quét trùng chỉ tốn thêm thời gian, còn bỏ
    sót trong im lặng thì hỏng đúng việc mà công cụ này sinh ra để làm.
    """
    if not status.st_dev or not status.st_ino:
        return None
    return (status.st_dev, status.st_ino)


def _looks_binary(path: Path) -> bool:
    """Chỉ tệp có phần mở rộng của một ngôn ngữ mới đi tới đây, nên "nhị phân"
    ở đây nghĩa là UTF-16 hoặc một khối dữ liệu bị đặt nhầm tên.

    Một byte NUL lẻ thì không đủ để kết luận: nhét đúng một byte đó vào chuỗi
    là đủ khiến cả tệp biến mất khỏi lần quét, trong khi Node, PHP hay trình
    thông dịch vẫn chạy tệp bình thường. Những thứ thật sự nhị phân có NUL
    dày đặc chứ không phải một hai byte.
    """
    try:
        with open(path, "rb") as handle:
            probe = handle.read(_BINARY_PROBE_BYTES)
    except OSError:
        return True
    return probe.count(b"\x00") > _MAX_STRAY_NULL_BYTES


def declared_python_encoding(raw: bytes) -> Optional[str]:
    """Cách CPython chọn bảng mã cho một tệp .py (PEP 263), hoặc None nếu tệp
    khai báo một bảng mã mà chính CPython cũng từ chối."""
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
    except SyntaxError:
        return None
    return encoding


def read_source(
    path: Path,
    language: Optional[str] = None,
    identity: Optional[Tuple[int, int]] = None,
) -> Tuple[str, bool]:
    """Đọc tệp, và nếu biết danh tính thì kiểm lại đúng thứ vừa mở ra.

    Giữa lúc liệt kê cây và lúc mở tệp có một khoảng trống. Ai ghi được vào
    cây đang bị quét có thể tráo tệp trong khoảng đó, khiến công cụ phân tích
    -- và trích đoạn vào báo cáo -- một nội dung khác hẳn thứ đã được xét
    duyệt. So `fstat` của chính handle đã mở với danh tính ghi nhận lúc duyệt
    sẽ đóng khoảng trống đó lại, vì kiểm trên handle chứ không kiểm lại
    đường dẫn.
    """
    with open(path, "rb") as handle:
        if identity is not None and _identity(os.fstat(handle.fileno())) != identity:
            raise FileChangedDuringScan(str(path))
        raw = handle.read()
    if language == PYTHON:
        return _decode_python(raw)
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        return raw.decode("utf-8"), False
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace"), True


# Các codec biến đổi byte-đối-byte: CPython chịu nhận chúng làm bảng mã nguồn
# nhưng chúng là vector bomb giải nén - một tệp 2 MB khai báo zlib_codec có
# thể giải nén thành hàng GB bên trong raw.decode(), ngoài mọi hạn mức của
# engine. Mã thật gần như không bao giờ khai báo chúng; bỏ qua khai báo và
# đọc theo UTF-8 như đối với bảng mã không tồn tại.
_BOMB_CODECS = frozenset(
    {
        "zlib-codec",
        "zlib",
        "bz2-codec",
        "bz2",
        "base64-codec",
        "base64",
        "quopri-codec",
        "quopri",
        "hex-codec",
        "hex",
        "uu-codec",
        "uu",
    }
)


def _decode_python(raw: bytes) -> Tuple[str, bool]:
    """Giải mã đúng như CPython sẽ làm khi chạy tệp này.

    Đọc cứng UTF-8 là một lỗ hổng thật: một tệp khai báo `# coding: utf-7` bị
    CPython đọc ra mã hoàn toàn khác với những gì đọc theo UTF-8 -- `+AAo-`
    trong UTF-7 là một dấu xuống dòng, nên thứ trông như một dòng chú thích
    lại là mã chạy được. Phân tích sai bản giải mã thì sink thật không bao giờ
    lọt vào AST.
    """
    encoding = declared_python_encoding(raw)
    if encoding is not None and encoding.lower().replace("_", "-") not in _BOMB_CODECS:
        try:
            return raw.decode(encoding), False
        except (LookupError, ValueError):  # ValueError bao cả UnicodeDecodeError
            pass
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.decode("utf-8", errors="replace"), True
