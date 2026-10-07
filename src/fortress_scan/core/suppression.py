"""Đọc chỉ thị `fortress-scan: ignore` nằm trong mã được quét.

Một nguyên tắc chi phối gần như toàn bộ module này: **chỉ thị nằm trong một
chuỗi không phải là chỉ thị**. Dòng dưới đây trông vô hại với người review
nhưng lại tắt tiếng cả tệp, và tắt trong im lặng::

    HELP = "# fortress-scan: ignore-file"

Nên trước khi dò chỉ thị, `_mask_string_literals` xoá trắng mọi nội dung nằm
trong chuỗi. Muốn xoá đúng thì phải biết chuỗi bắt đầu và kết thúc ở đâu, mà
luật đó khác nhau ở từng ngôn ngữ. Các bảng bên dưới mô tả bốn dạng chuỗi bắc
qua nhiều dòng, và mỗi bảng khai thiếu một ngôn ngữ là mở lại đúng một đường
lách:

* chuỗi thường còn mở khi hết dòng (`_SPANNING_QUOTES`);
* chuỗi nối dòng bằng dấu chéo ngược (`_LINE_CONTINUATION`);
* heredoc, đóng bằng nhãn do người viết đặt (`_HEREDOC_OPENERS`);
* chuỗi đóng bằng dấu cố định hoặc bằng thụt lề (`_BRACKET_STRINGS`,
  `_BLOCK_SCALAR_KEY`).

Bảng dấu mở chú thích chịu cùng luật đó theo chiều ngược lại: nhận nhầm một
toán tử là dấu mở chú thích thì phần đuôi dòng được phơi ra nguyên vẹn, và
một hằng chuỗi nằm sau nó lại tắt được cả tệp.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from ..languages import (
    C,
    CPP,
    CSHARP,
    DART,
    GO,
    GROOVY,
    JAVA,
    JAVASCRIPT,
    KOTLIN,
    LUA,
    MANIFEST,
    OBJC,
    PERL,
    PHP,
    POWERSHELL,
    PYTHON,
    RUBY,
    RUST,
    SCALA,
    SHELL,
    SWIFT,
    TYPESCRIPT,
    WORKFLOW,
)
from .model import Finding

# Nhánh dài phải đứng trước: lựa chọn trong regex là "khớp cái đầu tiên", nên
# đặt "ignore" lên đầu sẽ nuốt luôn tiền tố của "ignore-file" và
# "ignore-next-line", khiến hai phạm vi đó âm thầm rơi về "ignore" một dòng.
_DIRECTIVE = re.compile(
    r"(?:#|//|/\*|--|<!--)\s*fortress-scan\s*:\s*(ignore-next-line|ignore-file|ignore)"
    r"(?:\s*\[([A-Za-z0-9\-, ]{0,200})\])?"
    r"(?:\s*(?:--|:)\s*(?P<reason>[^\n*]{0,200}))?"
)

_MAX_LINES = 200_000

# Bộ mặt nạ chạy ngoài Budget của engine nên phải tự mang hạn mức: một dòng
# `${${${` không có dấu đóng bắt _scan_to_closer quét lại tới cuối dòng ở từng
# vị trí, tức là bậc hai.
#
# Đo trên mã thật thì việc quét này tuyến tính, nhiều nhất khoảng 1 bước mỗi ký
# tự; payload tấn công tốn 8.000 bước mỗi ký tự. Nên hạn mức đi theo kích thước
# tệp với hệ số 8: rộng gấp tám lần trường hợp hợp lệ nặng nhất mà vẫn chặn
# payload ngay.
_MASK_STEPS_PER_CHAR = 8
_MIN_MASK_STEPS = 100_000
_MAX_MASK_STEPS = 5_000_000


def _mask_step_allowance(lines: Sequence[str]) -> int:
    total = sum(len(text) for text in lines)
    return min(_MAX_MASK_STEPS, max(_MIN_MASK_STEPS, _MASK_STEPS_PER_CHAR * total))


class _MaskExhausted(Exception):
    """Dòng phức tạp bất thường; bỏ toàn bộ chỉ thị của tệp thay vì quét tiếp."""


class _MaskBudget:
    """Hạn mức riêng cho một tệp. Là đối tượng chứ không phải biến toàn cục vì
    engine chạy nhiều tệp song song qua ThreadPoolExecutor."""

    __slots__ = ("_remaining",)

    def __init__(self, steps: int) -> None:
        self._remaining = steps

    def spend(self) -> None:
        self._remaining -= 1
        if self._remaining <= 0:
            raise _MaskExhausted

# Tra theo từng ngôn ngữ, vì mỗi dấu ở đây lại là toán tử hợp lệ ở ngôn ngữ
# khác: `//` là phép chia nguyên của Python, `--` là toán tử giảm của
# JS/Java/C#/PHP, `#` là trường riêng tư của JavaScript. Nhận nhầm một trong số
# đó thì `mid = (lo + hi) // 2 ; NOTE = "# fortress-scan: ignore-file"` tắt
# sạch cả tệp. `--` chỉ có mặt ở Lua, nơi nó thật sự mở chú thích.
_LINE_COMMENTS: Dict[str, Tuple[str, ...]] = {
    PYTHON: ("#",),
    JAVASCRIPT: ("//",),
    TYPESCRIPT: ("//",),
    PHP: ("//", "#"),
    JAVA: ("//",),
    RUBY: ("#",),
    GO: ("//",),
    CSHARP: ("//",),
    SHELL: ("#",),
    MANIFEST: ("//",),
    RUST: ("//",),
    POWERSHELL: ("#",),
    PERL: ("#",),
    LUA: ("--",),
    WORKFLOW: ("#",),
    C: ("//",),
    CPP: ("//",),
    OBJC: ("//",),
    KOTLIN: ("//",),
    SCALA: ("//",),
    GROOVY: ("//",),
    SWIFT: ("//",),
    DART: ("//",),
}

# Trong shell, `#` chỉ mở chú thích khi nó BẮT ĐẦU một từ. `curl http://x/#frag`
# là một đối số bình thường, không phải chú thích -- mà chỉ cần coi nhầm là chú
# thích thì phần đuôi dòng lọt ra nguyên vẹn và
# `curl http://x/#frag; M="# fortress-scan: ignore-file"` lại tắt được cả tệp.
# Python, Ruby và PHP không có luật này: ở đó `x=1#ghi chú` đúng là chú thích.
_WORD_START_LINE_COMMENTS: FrozenSet[str] = frozenset({SHELL})

# Chú thích khối phải được đóng lại chứ không nuốt trọn phần đuôi dòng: sau
# `*/` là mã thật, và mã thật thì chứa được chuỗi.
#
# `<!--` vắng mặt dù nhiều tệp lai HTML dùng nó, vì `a <!--b` là biểu thức hợp
# lệ trong Java, C#, JavaScript và PHP. Bỏ nó đi không làm mất chỉ thị thật:
# bảng này chỉ quyết định có phơi phần đuôi dòng ra hay không, còn
# `<!-- fortress-scan: ignore-file -->` vẫn tới được bộ dò như thường.
_C_COMMENT: Tuple[str, str] = ("/*", "*/")
_BLOCK_COMMENTS: Dict[str, Tuple[Tuple[str, str], ...]] = {
    PYTHON: (),
    JAVASCRIPT: (_C_COMMENT,),
    TYPESCRIPT: (_C_COMMENT,),
    PHP: (_C_COMMENT,),
    JAVA: (_C_COMMENT,),
    RUBY: (),
    GO: (_C_COMMENT,),
    CSHARP: (_C_COMMENT,),
    SHELL: (),
    MANIFEST: (_C_COMMENT,),
    RUST: (_C_COMMENT,),
    POWERSHELL: (("<#", "#>"),),
    # Perl có POD và Lua có `--[[ ]]`, nhưng cả hai đều bắt đầu bằng dấu mở
    # chú thích DÒNG của chính ngôn ngữ đó, nên nhánh chú thích dòng đã lo.
    # Khai `/* */` cho chúng như mặc định mới là sai: `/*` không mở gì trong
    # Perl hay Lua, và một dấu mở chú thích không có thật là một đường lách.
    PERL: (),
    LUA: (),
    WORKFLOW: (),
    C: (_C_COMMENT,),
    CPP: (_C_COMMENT,),
    OBJC: (_C_COMMENT,),
    KOTLIN: (_C_COMMENT,),
    SCALA: (_C_COMMENT,),
    GROOVY: (_C_COMMENT,),
    SWIFT: (_C_COMMENT,),
    DART: (_C_COMMENT,),
}

# Ngôn ngữ lạ thì nhận cả hai dấu phổ biến: thà nhận dư một dấu mở chú thích còn
# hơn bỏ qua chỉ thị thật của người dùng ở một định dạng chưa khai báo. Mọi lối
# vào thật đều truyền language, nên nhánh này không chạm mã được quét.
_DEFAULT_LINE_COMMENTS: Tuple[str, ...] = ("//", "#")
_DEFAULT_BLOCK_COMMENTS: Tuple[Tuple[str, str], ...] = (_C_COMMENT,)

# Dấu nháy nào giữ chuỗi mở khi hết dòng. Bộ mặt nạ đóng chuỗi ở cuối dòng,
# nên khai thiếu ở đây là để dòng kế tiếp ( vẫn nằm trong chuỗi theo cách ngôn
# ngữ thật đọc nó ) rơi ra đọc như mã, và một dấu `#` ở đó tắt cả tệp.
#
# C# có chuỗi nguyên văn `@"..."` nhưng không cần nhận tiền tố `@`: cờ này chỉ
# có tác dụng đúng lúc chuỗi còn mở khi hết dòng.
_SPANNING_QUOTES: Dict[str, FrozenSet[str]] = {
    PYTHON: frozenset(),
    JAVASCRIPT: frozenset("`"),
    TYPESCRIPT: frozenset("`"),
    PHP: frozenset("\"'"),
    JAVA: frozenset(),
    RUBY: frozenset("\"'"),
    GO: frozenset("`"),
    CSHARP: frozenset('"'),
    SHELL: frozenset("\"'"),
    MANIFEST: frozenset(),
    # Chuỗi nháy kép của Rust chứa được ký tự xuống dòng, không cần dấu gì thêm.
    RUST: frozenset('"'),
    # Perl cũng vậy, với cả hai loại nháy.
    PERL: frozenset("\"'"),
    # PowerShell và Lua thì không: chuỗi một dòng của chúng phải đóng trong
    # dòng của nó. Dạng nhiều dòng của hai ngôn ngữ này là here-string `@"`
    # và chuỗi ngoặc `[[`, xử lý ở _BRACKET_STRINGS.
    POWERSHELL: frozenset(),
    LUA: frozenset(),
    # Scalar đặt trong nháy của YAML bắc qua nhiều dòng mà không cần dấu gì
    # thêm, nên nó là chỗ giấu chỉ thị y hệt heredoc của PHP:
    #     env:
    #       MO_TA: "tài liệu
    #     # fortress-scan: ignore-file"
    # Với YAML, cả hai dòng là MỘT chuỗi. Không dòng nào là chú thích.
    WORKFLOW: frozenset("\"'"),
    # Chuỗi thường của C phải đóng trong dòng ( trừ dấu \ cuối dòng, xem
    # _LINE_CONTINUATION ). C++ có raw string R"( ... )" bắc qua nhiều dòng.
    C: frozenset(),
    CPP: frozenset('"'),
    OBJC: frozenset(),
    # Chuỗi một dòng của Kotlin, Scala, Groovy phải đóng trong dòng; dạng nhiều
    # dòng là ba nháy, đã có trong danh sách ba nháy chung.
    KOTLIN: frozenset(),
    SCALA: frozenset(),
    GROOVY: frozenset(),
    SWIFT: frozenset(),
    DART: frozenset(),
}
_DEFAULT_SPANNING_QUOTES: FrozenSet[str] = frozenset("`")

# Ngôn ngữ mà dấu chéo ngược cuối dòng nuốt luôn ký tự xuống dòng và giữ chuỗi
# mở sang dòng sau. Cùng một đường lách với bảng trên, chỉ tốn thêm một ký tự.
_LINE_CONTINUATION: FrozenSet[str] = frozenset(
    {PYTHON, JAVASCRIPT, TYPESCRIPT, SHELL, C, CPP, OBJC}
)

# Heredoc là dạng chuỗi nhiều dòng thứ ba, và là cách tự nhiên nhất để viết
# một đoạn văn bản dài trong PHP, Ruby hay shell. Nhãn đặt được trong nháy
# ( nowdoc của PHP, `<<~'EOT'` của Ruby ). Riêng Ruby và Perl, `<<` trần còn là
# toán tử dịch trái, nên nhánh không có `-`/`~` chỉ nhận nhãn viết hoa để
# `arr << item` không bị hiểu nhầm.
_HEREDOC_LABEL = r"[A-Za-z_][A-Za-z0-9_]*"

# Ba cách viết nhãn heredoc: "EOT", 'EOT' ( nowdoc, không nội suy ) và EOT trần.
_HEREDOC_NAME = r"(?:\"(?P<dq>%s)\"|'(?P<sq>%s)'|\\?(?P<bare>%s))" % (
    _HEREDOC_LABEL,
    _HEREDOC_LABEL,
    _HEREDOC_LABEL,
)

_HEREDOC_OPENERS: Dict[str, "re.Pattern[str]"] = {
    PHP: re.compile(r"<<<[ \t]*" + _HEREDOC_NAME),
    # Nhánh có `-`/`~` nhận nhãn bất kỳ. Nhánh `<<` trần nhận nhãn viết
    # thường lẫn viết hoa, vì Ruby cũng nhận: `<<eot` là một heredoc thật.
    # Thứ tách nó khỏi toán tử dịch trái là KHOẢNG TRẮNG chứ không phải kiểu chữ:
    # `arr << item` có dấu cách nên không khớp, còn `arr <<item` thì chính Ruby
    # cũng đọc là heredoc. Đòi viết hoa chỉ còn tác dụng làm đường lách.
    RUBY: re.compile(
        r"<<(?P<squiggly>[-~])[ \t]*" + _HEREDOC_NAME
        + r"|<<(?P<plain>[A-Za-z_][A-Za-z0-9_]*)"
    ),
    SHELL: re.compile(r"<<(?!<)(?P<dash>-)?[ \t]*" + _HEREDOC_NAME),
    # Perl dùng cùng cú pháp với shell và mang cùng chỗ mập mờ với Ruby.
    # Nhãn trần ở đây nhận mọi kiểu chữ và phải dính liền sau `<<`, vì đó
    # đúng là cách Perl phân biệt heredoc với phép dịch trái. `<<eot` viết
    # thường là heredoc hợp lệ ( đã chạy thử trên perl 5.42 ), nên bắt nhãn phải
    # viết hoa là để ngỏ một đường tắt tiếng cả tệp: thân heredoc bị đọc
    # như mã, và một dấu `#` trong đó mang theo `ignore-file`.
    PERL: re.compile(
        r"<<(?P<squiggly>~)?[ \t]*(?:\"(?P<dq>%s)\"|'(?P<sq>%s)')"
        r"|<<(?P<tilde>~)?(?P<plain>[A-Za-z_][A-Za-z0-9_]*)"
        % (_HEREDOC_LABEL, _HEREDOC_LABEL)
    ),
}

# Dạng thứ tư: chuỗi nhiều dòng đóng bằng dấu CỐ ĐỊNH, không có nhãn do người
# viết đặt. Dấu mở dài đứng trước dấu ngắn để `[=[` không bị `[[` cướp mất.
_BRACKET_STRINGS: Dict[str, Tuple[Tuple[str, str], ...]] = {
    LUA: (("[==[", "]==]"), ("[=[", "]=]"), ("[[", "]]")),
    POWERSHELL: (('@"', '"@'), ("@'", "'@")),
    # Chuỗi dollar-slashy của Groovy bắc qua nhiều dòng.
    GROOVY: (("$/", "/$"),),
}

# Dạng thứ năm, và là dạng duy nhất mà NGƯỜI VIẾT tự chọn lấy dấu đóng:
# `%q{...}` của Ruby và `q(...)` của Perl đều là hằng chuỗi. Không mô tả chúng
# thì ruột của chúng được đọc như mã, nên
#
#     n = %q{# fortress-scan: ignore-file}
#
# tắt sạch phát hiện của cả tệp, dù trong Ruby dòng đó không có lấy một chú
# thích nào: đó là một chuỗi.
#
# Dấu mở đứng ngay sau tên dạng, và ký tự đó QUYẾT ĐỊNH dấu đóng: bốn cặp
# ngoặc đóng bằng ngoặc đối ứng ( và lồng nhau được ), mọi ký tự khác đóng
# bằng chính nó.
#
# Lookbehind giữ cho toán tử chia lấy dư và tên biến không bị nhận nhầm:
# `a % b` có dấu cách nên rơi ra ngoài, `x%2` có chữ số nên cũng vậy, còn
# `$q->param(...)` của Perl bị chặn bởi `$` đứng trước.
_PERCENT_STRINGS: Dict[str, "re.Pattern[str]"] = {
    RUBY: re.compile(r"(?<![\w)\]}])%[qQwWiIrsx]?(?P<delim>[^\s\w=])"),
    PERL: re.compile(r"(?<![\w$@%&>-])(?:qq|qw|qr|q)[ 	]{0,2}(?P<delim>[^\s\w])"),
}

# Ngoặc mở thì đóng bằng ngoặc đối ứng và đếm được độ sâu; ký tự khác đóng
# bằng chính nó, và khi đó không có chuyện lồng nhau.
_PERCENT_PAIRS: Dict[str, str] = {"(": ")", "[": "]", "{": "}", "<": ">"}

# Khối scalar của YAML: `mo_ta: |` hoặc `- run: >-`. Phần thân đóng bằng thụt
# lề chứ không bằng một dấu đóng, nên nó cần một cơ chế riêng.
_BLOCK_SCALAR_LANGUAGES: FrozenSet[str] = frozenset({WORKFLOW})
_BLOCK_SCALAR_KEY = re.compile(
    r"^([ \t]*)(?:-[ \t]+)?[A-Za-z_][\w.-]*[ \t]*:[ \t]*[|>][+-]?\d{0,3}[ \t]*$"
)

# `<<-` ( shell, Ruby ) và `<<~` ( Ruby ) cho phép thụt lề dòng kết thúc; PHP
# 7.3 trở đi cũng vậy. Nhận dư một dòng kết thúc là đóng heredoc SỚM hơn thật,
# tức là phơi phần đuôi ra làm mã -- nên chỉ bật cờ này đúng ở nơi ngôn ngữ
# thật sự cho phép.
_HEREDOC_INDENT_GROUPS: Tuple[str, ...] = ("squiggly", "dash", "tilde")
_HEREDOC_INDENTED_ALWAYS: FrozenSet[str] = frozenset({PHP})

_HEREDOC_LABEL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)


@dataclass(frozen=True)
class _CommentSyntax:
    """Cú pháp chú thích và chuỗi của một ngôn ngữ, đã sắp dài trước ngắn."""

    line: Tuple[str, ...]
    block: Tuple[Tuple[str, str], ...]
    word_start_only: bool = False
    spanning: FrozenSet[str] = _DEFAULT_SPANNING_QUOTES
    continuation: bool = True
    heredoc: Optional["re.Pattern[str]"] = None
    heredoc_indented: bool = False
    brackets: Tuple[Tuple[str, str], ...] = ()
    block_scalars: bool = False
    percent: Optional["re.Pattern[str]"] = None


def comment_syntax(language: Optional[str]) -> _CommentSyntax:
    if language is None:
        return _CommentSyntax(_DEFAULT_LINE_COMMENTS, _DEFAULT_BLOCK_COMMENTS)
    return _CommentSyntax(
        _LINE_COMMENTS.get(language, _DEFAULT_LINE_COMMENTS),
        _BLOCK_COMMENTS.get(language, _DEFAULT_BLOCK_COMMENTS),
        language in _WORD_START_LINE_COMMENTS,
        _SPANNING_QUOTES.get(language, _DEFAULT_SPANNING_QUOTES),
        language in _LINE_CONTINUATION,
        _HEREDOC_OPENERS.get(language),
        language in _HEREDOC_INDENTED_ALWAYS,
        _BRACKET_STRINGS.get(language, ()),
        language in _BLOCK_SCALAR_LANGUAGES,
        _PERCENT_STRINGS.get(language),
    )


# Ba nháy giữ nguyên danh sách chung: Python có `"""`/`'''`, Java có text
# block và C# 11 có raw string literal, đều viết bằng ba nháy. Ở những ngôn
# ngữ còn lại `"""` là chuỗi rỗng rồi tới một dấu nháy mở, và coi nó là một
# vùng ba nháy chỉ khiến bộ mặt nạ xoá RỘNG hơn -- tức là về phía không giấu
# chỉ thị nào, đúng hướng an toàn.
_TRIPLE_QUOTES: Tuple[str, ...] = ('"""', "'''")
_LINE_QUOTES: Tuple[str, ...] = ('"', "'", "`")
# Vùng nội suy bên trong chuỗi là mã, nên nó được phép chứa một chuỗi lồng
# dùng đúng dấu nháy đang mở -- `outer ${`inner`} end` là JavaScript hợp lệ.
# Không nhảy qua trọn vùng này thì dấu nháy mở của chuỗi lồng bị hiểu nhầm là
# dấu đóng của chuỗi ngoài, phần ruột rơi ra ngoài và một chỉ thị nằm trong
# dữ liệu lại được tính như chú thích thật.
_INTERPOLATION_MARKERS: Tuple[Tuple[str, str], ...] = (("${", "}"), ("#{", "}"), ("{$", "}"))


def _starts_with_any(text: str, index: int, options: Tuple[str, ...]) -> Optional[str]:
    for option in options:
        if text.startswith(option, index):
            return option
    return None


def _skip_nested_quote(raw: str, index: int, budget: _MaskBudget) -> int:
    quote = raw[index]
    cursor = index + 1
    length = len(raw)
    while cursor < length:
        budget.spend()
        if raw[cursor] == "\\":
            cursor += 2
            continue
        if raw[cursor] == quote:
            return cursor + 1
        cursor += 1
    return cursor


def _interpolation_end(raw: str, index: int, budget: _MaskBudget) -> int:
    """Chỉ số ngay sau dấu đóng khớp của vùng nội suy, hoặc -1 nếu không có."""
    for opener, closer in _INTERPOLATION_MARKERS:
        if raw.startswith(opener, index):
            return _scan_to_closer(raw, index + len(opener), opener, closer, budget)
    return -1


def _scan_to_closer(
    raw: str, cursor: int, opener: str, closer: str, budget: _MaskBudget
) -> int:
    depth = 1
    length = len(raw)
    while cursor < length:
        budget.spend()
        char = raw[cursor]
        if char == "\\":
            cursor += 2
            continue
        if char in ("'", '"', "`"):
            cursor = _skip_nested_quote(raw, cursor, budget)
            continue
        if raw.startswith(opener, cursor):
            depth += 1
            cursor += len(opener)
            continue
        if char == closer:
            depth -= 1
            cursor += 1
            if depth == 0:
                return cursor
            continue
        cursor += 1
    return -1


@dataclass(frozen=True)
class _Region:
    """Một vùng đang mở và bắc qua cuối dòng."""

    closer: str
    keep: bool
    heredoc: bool = False
    indented: bool = False
    # Khối YAML đóng bằng THỤT LỀ chứ không bằng một dấu đóng: mọi dòng thụt
    # sâu hơn con số này còn thuộc về nó. -1 nghĩa là vùng này không phải khối
    # YAML.
    scalar_indent: int = -1
    # Dấu MỞ của vùng, chỉ đặt cho chuỗi phần trăm dùng cặp ngoặc. Có nó
    # thì `%q{a{b}c}` đếm được độ sâu và đóng đúng ở dấu cuối; rỗng nghĩa
    # là vùng đóng ngay ở dấu đóng đầu tiên, y như trước.
    nest: str = ""


Pending = _Region


def _find_string_end(
    raw: str, index: int, delimiter: str, budget: _MaskBudget, nest: str = ""
) -> int:
    """Vị trí dấu đóng THẬT của một vùng chuỗi, tôn trọng dấu thoát.

    `str.find` trần là một đường lách. Trong chuỗi ba nháy của Python, một dấu
    nháy đứng sau gạch chéo ngược là dấu nháy được THOÁT chứ không phải dấu
    đóng: mở một docstring, cho dòng thứ hai chứa gạch chéo ngược rồi ba nháy,
    thì với CPython chuỗi vẫn còn đang mở và dòng thứ ba vẫn là nội dung của
    nó. Bộ mặt nạ thì đóng chuỗi ngay ở dòng thứ hai rồi đọc dòng thứ ba như
    mã -- nên một dòng `# fortress-scan: ignore-file` nằm gọn trong docstring
    tắt sạch phát hiện của cả tệp. Xem tests/test_suppression_string_desync.py.

    Dấu gạch chéo ngược ở cuối dòng nuốt luôn ký tự xuống dòng, nên `cursor`
    vượt quá độ dài và vùng được giữ mở sang dòng sau -- đúng như ngôn ngữ đọc.
    """
    cursor = index
    depth = 1
    length = len(raw)
    while cursor < length:
        budget.spend()
        if raw[cursor] == "\\":
            cursor += 2
            continue
        if nest and raw.startswith(nest, cursor):
            depth += 1
            cursor += len(nest)
            continue
        if raw.startswith(delimiter, cursor):
            depth -= 1
            if depth == 0:
                return cursor
            cursor += len(delimiter)
            continue
        cursor += 1
    return -1


def _close_region(
    raw: str, index: int, region: _Region, budget: _MaskBudget
) -> Tuple[str, int, Optional[Pending]]:
    """Đọc tới dấu đóng của một vùng đang mở, bắc qua dòng nếu cần.

    `keep` phân biệt hai loại vùng. Thân chuỗi bị xoá trắng vì chỉ thị nằm
    trong đó là dữ liệu, và trong đó `\\` là dấu thoát. Thân chú thích khối
    được giữ nguyên vì chỉ thị nằm trong đó là chú thích thật, và ở đó `\\`
    không có nghĩa gì cả -- nên chỉ vùng chuỗi mới đi qua _find_string_end.
    """
    delimiter = region.closer
    if region.keep:
        end = raw.find(delimiter, index)
    else:
        end = _find_string_end(raw, index, delimiter, budget, region.nest)
    if end < 0:
        body = raw[index:] if region.keep else " " * (len(raw) - index)
        return body, len(raw), region
    body = raw[index:end] if region.keep else " " * (end - index)
    return body + delimiter, end + len(delimiter), None


def _consume_quoted(
    raw: str, index: int, quote: str, budget: _MaskBudget, syntax: _CommentSyntax
) -> Tuple[str, int, Optional[Pending]]:
    """Xoá thân một chuỗi một nháy, tôn trọng dấu thoát."""
    pieces = [quote]
    index += 1
    length = len(raw)
    continued = False
    while index < length:
        char = raw[index]
        if char == "\\":
            pieces.append(" ")
            index += 1
            if index < length:
                pieces.append(" ")
                index += 1
            else:
                # Gạch chéo ngược cuối dòng nuốt luôn ký tự xuống dòng: ở
                # những ngôn ngữ có luật này, chuỗi còn mở sang dòng sau.
                continued = True
            continue
        end = _interpolation_end(raw, index, budget)
        if end != -1:
            # Cả vùng nội suy bị xoá trắng: bên trong là mã, nhưng ở đây ta chỉ
            # cần nó không sinh ra chỉ thị, và xoá là hướng an toàn.
            pieces.append(" " * (end - index))
            index = end
            continue
        if char == quote:
            pieces.append(quote)
            return "".join(pieces), index + 1, None
        pieces.append(" ")
        index += 1
    if quote in syntax.spanning or (continued and syntax.continuation):
        # Vùng còn mở. Trả về đúng dạng Pending mà _mask_line chờ đợi: chỗ này
        # từng trả về một chuỗi một ký tự, nên `delimiter, keep = pending` ở
        # dòng sau ném ValueError và giết cả lượt quét -- một tệp .js có một
        # dấu backtick lẻ là đủ để không tệp nào trong cây được báo cáo.
        return "".join(pieces), length, _Region(quote, False)
    return "".join(pieces), length, None


def _starts_block_comment(
    raw: str, index: int, blocks: Tuple[Tuple[str, str], ...]
) -> Optional[Tuple[str, str]]:
    for opener, closer in blocks:
        if raw.startswith(opener, index):
            return opener, closer
    return None


def _starts_line_comment(raw: str, index: int, syntax: _CommentSyntax) -> bool:
    if _starts_with_any(raw, index, syntax.line) is None:
        return False
    if not syntax.word_start_only:
        return True
    return index == 0 or raw[index - 1].isspace()


def _opens_heredoc(raw: str, index: int, syntax: _CommentSyntax) -> Optional[_Region]:
    """Nhãn heredoc mở ra tại đúng vị trí này, nếu có."""
    if syntax.heredoc is None or raw[index] != "<":
        return None
    match = syntax.heredoc.match(raw, index)
    if match is None:
        return None
    groups = match.groupdict()
    label = next(
        (
            value
            for name, value in groups.items()
            if value is not None and name not in _HEREDOC_INDENT_GROUPS
        ),
        None,
    )
    if label is None:
        return None
    indented = syntax.heredoc_indented or any(
        groups.get(name) for name in _HEREDOC_INDENT_GROUPS
    )
    return _Region(label, keep=False, heredoc=True, indented=indented)


def _opens_block_scalar(masked: str, syntax: _CommentSyntax) -> Optional[_Region]:
    """Dòng này có mở một khối scalar của YAML không (`mo_ta: |`).

    Thân khối là dữ liệu trọn dòng, và nó đóng bằng thụt lề chứ không bằng một
    dấu đóng. Không mô tả nó thì thân khối được đọc như mã, và một dấu `#` ở
    đầu dòng trong đó mở ra một "chú thích" đủ để tắt cả tệp:

        env:
          MO_TA: |
            # fortress-scan: ignore-file

    Đây đúng là quyết định đã áp cho heredoc của shell: thân heredoc cũng
    thường là script thật, mà vẫn bị che, vì người dùng muốn tắt cảnh báo thì
    viết chỉ thị ở tầng ngôn ngữ bao ngoài chứ không viết lẫn vào dữ liệu.
    """
    if not syntax.block_scalars:
        return None
    match = _BLOCK_SCALAR_KEY.match(masked)
    if match is None:
        return None
    return _Region("", keep=False, scalar_indent=len(match.group(1)))


def _continues_block_scalar(raw: str, region: _Region) -> bool:
    """Dòng trống, hoặc dòng thụt sâu hơn khoá đã mở khối, thì vẫn ở trong khối."""
    if not raw.strip():
        return True
    return len(raw) - len(raw.lstrip()) > region.scalar_indent


def _starts_bracket_string(
    raw: str, index: int, brackets: Tuple[Tuple[str, str], ...]
) -> Optional[Tuple[str, str]]:
    """Cặp mở/đóng của chuỗi nhiều dòng bắt đầu đúng tại vị trí này."""
    for opener, closer in brackets:
        if raw.startswith(opener, index):
            return opener, closer
    return None


def _starts_percent_string(
    raw: str, index: int, syntax: _CommentSyntax
) -> Optional[Tuple[str, str, str]]:
    """Chuỗi phần trăm mở ra tại đúng vị trí này: (phần mở, dấu đóng, dấu lồng).

    Dấu đóng do chính người viết chọn, nên nó phải đọc ra từ dòng chứ không
    tra được trong bảng. Bốn cặp ngoặc lồng nhau được nên trả về thêm dấu mở;
    mọi ký tự khác đóng bằng chính nó và không có độ sâu để đếm.
    """
    if syntax.percent is None:
        return None
    match = syntax.percent.match(raw, index)
    if match is None:
        return None
    delimiter = match.group("delim")
    closer = _PERCENT_PAIRS.get(delimiter, delimiter)
    nest = delimiter if closer != delimiter else ""
    return match.group(0), closer, nest


def _closes_heredoc(raw: str, region: _Region) -> bool:
    """Dòng này có đúng là dòng kết thúc heredoc không.

    Nhận dư một dòng kết thúc là đóng heredoc sớm hơn ngôn ngữ thật, tức là
    phơi phần thân còn lại ra làm mã -- nên nhãn phải đứng trọn vẹn, không
    được chỉ là tiền tố của một từ dài hơn ( `EOT` không đóng `EOTHER` ).
    """
    text = raw.lstrip() if region.indented else raw
    if not text.startswith(region.closer):
        return False
    rest = text[len(region.closer) :]
    return not rest[:1] or rest[0] not in _HEREDOC_LABEL_CHARS


def _mask_line(
    raw: str, pending: Optional[Pending], budget: _MaskBudget, syntax: _CommentSyntax
) -> Tuple[str, Optional[Pending]]:
    pieces: List[str] = []
    index = 0
    length = len(raw)
    # Thân heredoc là dữ liệu trọn dòng: không có mã nào nằm cùng dòng với nó,
    # nên nó được xử lý trước vòng lặp thay vì bên trong.
    if pending is not None and pending.scalar_indent >= 0:
        if _continues_block_scalar(raw, pending):
            return " " * length, pending
        pending = None
    if pending is not None and pending.heredoc:
        if not _closes_heredoc(raw, pending):
            return " " * length, pending
        pending = None
    # Heredoc mở ra ở dòng NÀY nhưng thân của nó bắt đầu ở dòng SAU, nên nó
    # được giữ riêng: gán thẳng vào `pending` sẽ nuốt luôn phần đuôi dòng này.
    opened: Optional[_Region] = None
    while index < length:
        if pending is not None:
            text, index, pending = _close_region(raw, index, pending, budget)
            pieces.append(text)
            continue
        block = _starts_block_comment(raw, index, syntax.block)
        if block is not None:
            opener, closer = block
            pieces.append(opener)
            text, index, pending = _close_region(
                raw, index + len(opener), _Region(closer, True), budget
            )
            pieces.append(text)
            continue
        if _starts_line_comment(raw, index, syntax):
            pieces.append(raw[index:])
            break
        bracket = _starts_bracket_string(raw, index, syntax.brackets)
        if bracket is not None:
            pieces.append(bracket[0])
            text, index, pending = _close_region(
                raw, index + len(bracket[0]), _Region(bracket[1], False), budget
            )
            pieces.append(text)
            continue
        percent = _starts_percent_string(raw, index, syntax)
        if percent is not None:
            head, closer, nest = percent
            pieces.append(head)
            text, index, pending = _close_region(
                raw,
                index + len(head),
                _Region(closer, False, nest=nest),
                budget,
            )
            pieces.append(text)
            continue
        opener = _starts_with_any(raw, index, _TRIPLE_QUOTES)
        if opener is not None:
            pieces.append(opener)
            text, index, pending = _close_region(
                raw, index + len(opener), _Region(opener, False), budget
            )
            pieces.append(text)
            continue
        quote = _starts_with_any(raw, index, _LINE_QUOTES)
        if quote is not None:
            text, index, pending = _consume_quoted(raw, index, quote, budget, syntax)
            pieces.append(text)
            continue
        if opened is None:
            opened = _opens_heredoc(raw, index, syntax)
        pieces.append(raw[index])
        index += 1
    masked = "".join(pieces)
    if pending is None and opened is None:
        opened = _opens_block_scalar(masked, syntax)
    return masked, pending if pending is not None else opened


def _mask_string_literals(
    lines: Sequence[str], syntax: _CommentSyntax
) -> List[str]:
    """Thay nội dung chuỗi bằng khoảng trắng, giữ nguyên phần chú thích.

    Dấu mở chú thích được xét trước dấu nháy, nên dấu nháy đơn nằm trong chính
    chú thích (kiểu "don't") không bị hiểu nhầm là mở chuỗi.
    """
    budget = _MaskBudget(_mask_step_allowance(lines))
    masked: List[str] = []
    pending: Optional[Pending] = None
    for raw in lines:
        text, pending = _mask_line(raw, pending, budget, syntax)
        masked.append(text)
    return masked


@dataclass(frozen=True)
class Suppression:
    line: int
    rules: Tuple[str, ...]
    scope: str
    reason: str

    def covers(self, finding: Finding) -> bool:
        if self.rules and finding.rule_id not in self.rules:
            return False
        if self.scope == "ignore-file":
            return True
        if self.scope == "ignore-next-line":
            return finding.line == self.line + 1
        return finding.line == self.line


class SuppressionIndex:
    def __init__(
        self, suppressions: Sequence[Suppression], overflowed: bool = False
    ) -> None:
        self._suppressions = tuple(suppressions)
        self._overflowed = overflowed

    def __bool__(self) -> bool:
        return bool(self._suppressions)

    @property
    def overflowed(self) -> bool:
        """Hạn mức đã cạn nên không chỉ thị nào được tôn trọng.

        Cùng hướng an toàn với IgnoreSet.overflowed: bỏ hết quy tắc thì không
        phát hiện nào bị giấu, và engine nói ra chuyện đó trong báo cáo.
        """
        return self._overflowed

    @classmethod
    def from_lines(
        cls, lines: Sequence[str], language: Optional[str] = None
    ) -> "SuppressionIndex":
        window = lines[:_MAX_LINES]
        # Đa số tệp không nhắc tới công cụ này; khỏi cần xoá chuỗi làm gì.
        if not any("fortress-scan" in text for text in window):
            return cls(())
        try:
            masked = _mask_string_literals(window, comment_syntax(language))
        except _MaskExhausted:
            return cls((), overflowed=True)
        found: List[Suppression] = []
        for index, text in enumerate(masked, start=1):
            if "fortress-scan" not in text:
                continue
            match = _DIRECTIVE.search(text)
            if match is None:
                continue
            raw_rules = match.group(2) or ""
            rules = tuple(
                item.strip().upper() for item in raw_rules.split(",") if item.strip()
            )
            found.append(
                Suppression(
                    line=index,
                    rules=rules,
                    scope=match.group(1),
                    reason=(match.group("reason") or "").strip(),
                )
            )
        return cls(found)

    def suppresses(self, finding: Finding) -> bool:
        for suppression in self._suppressions:
            if suppression.covers(finding):
                return True
        return False


def partition(
    findings: Sequence[Finding], index: SuppressionIndex
) -> Tuple[List[Finding], int]:
    if not index:
        return list(findings), 0
    kept: List[Finding] = []
    removed = 0
    for finding in findings:
        if index.suppresses(finding):
            removed += 1
        else:
            kept.append(finding)
    return kept, removed
