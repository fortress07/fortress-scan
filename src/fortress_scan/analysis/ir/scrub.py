"""Xóa nội dung chuỗi và chú thích, GIỮ NGUYÊN độ dài.

Vì sao cần: bộ dò webshell kết luận trên dấu hiệu dạng chuỗi con, và chuỗi con
không phân biệt được `eval(` được GỌI với `"eval("` được NHẮC TỚI. Khác biệt đó
là toàn bộ khác biệt giữa một webshell và một tệp nói về webshell -- bộ quy tắc
WAF, luật YARA, corpus kiểm thử của một công cụ bảo mật, hay chính tệp
`indicators.py` ngay bên cạnh đây. Bản đầu của bộ dò này báo nhầm đúng vào
`indicators.py` và `__init__.py` của chính nó, và `test_samples_corpus.py` bắt
được ngay trong lần chạy đầu.

Phép xóa thay từng ký tự bên trong chuỗi và chú thích bằng dấu cách thay vì cắt
chúng đi. Giữ độ dài là điều kiện bắt buộc, không phải tiện lợi: vị trí dòng và
cột báo cho người đọc được tính bằng offset trên văn bản này, nên một phép cắt
sẽ làm mọi phát hiện trỏ lệch sang chỗ khác -- đúng lớp lỗi mà
`test_position_accuracy.py` và `test_line_desync.py` canh.

Giới hạn đã biết và cố ý: dấu nháy đơn, nháy kép đóng ở cuối dòng nếu chưa
đóng, vì đó là cách gần hết ngôn ngữ ở đây xử lý và vì nó chặn thiệt hại khi
một tệp có nháy lệch -- không có dòng này thì một dấu nháy lẻ sẽ xóa sạch phần
còn lại của tệp và bộ dò hóa mù. POD của Perl và `=begin` của Ruby không được
xử lý; dấu hiệu nằm trong đó vẫn bị coi là mã.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

from ...languages import (
    CSHARP,
    JAVA,
    JAVASCRIPT,
    PERL,
    PHP,
    POWERSHELL,
    PYTHON,
    RUBY,
    SHELL,
    TYPESCRIPT,
)


@dataclass(frozen=True)
class _Syntax:
    line_comments: Tuple[str, ...] = ()
    block_comments: Tuple[Tuple[str, str], ...] = ()
    quotes: Tuple[str, ...] = ()
    long_quotes: Tuple[str, ...] = ()


_C_LIKE = _Syntax(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    quotes=('"', "'"),
)

_SYNTAX: Dict[str, _Syntax] = {
    # `#` cũng là chú thích trong PHP, không chỉ `//`.
    PHP: _Syntax(
        line_comments=("//", "#"),
        block_comments=(("/*", "*/"),),
        quotes=('"', "'"),
    ),
    JAVA: _C_LIKE,
    CSHARP: _C_LIKE,
    # Backtick của JS là chuỗi mẫu, nên nội dung trong đó là dữ liệu.
    JAVASCRIPT: _Syntax(
        line_comments=("//",),
        block_comments=(("/*", "*/"),),
        quotes=('"', "'", "`"),
    ),
    TYPESCRIPT: _Syntax(
        line_comments=("//",),
        block_comments=(("/*", "*/"),),
        quotes=('"', "'", "`"),
    ),
    PYTHON: _Syntax(
        line_comments=("#",),
        quotes=('"', "'"),
        long_quotes=('"""', "'''"),
    ),
    # Backtick của shell, Perl và Ruby KHÔNG phải chuỗi: nó chạy lệnh. Xóa nó
    # đi là tự gỡ mất một trong những sink quan trọng nhất của ba ngôn ngữ này.
    SHELL: _Syntax(line_comments=("#",), quotes=('"', "'")),
    PERL: _Syntax(line_comments=("#",), quotes=('"', "'")),
    RUBY: _Syntax(line_comments=("#",), quotes=('"', "'")),
    POWERSHELL: _Syntax(
        line_comments=("#",),
        block_comments=(("<#", "#>"),),
        quotes=('"', "'"),
    ),
}


_LONG_QUOTE = 0
_LINE_COMMENT = 1
_BLOCK_COMMENT = 2
_QUOTE = 3

# (mở, loại, đóng). Thứ tự quyết định khi hai token cùng bắt đầu ở một vị trí:
# `"""` phải thắng `"`, nên nhóm chuỗi nhiều dòng đứng trước nhóm chuỗi một
# dòng. Dựng sẵn một lần lúc nạp mô-đun thay vì mỗi lần gọi.
_Token = Tuple[str, int, str]


def _build_tokens(syntax: _Syntax) -> Tuple[_Token, ...]:
    tokens: list = []
    for delimiter in syntax.long_quotes:
        tokens.append((delimiter, _LONG_QUOTE, delimiter))
    for marker in syntax.line_comments:
        tokens.append((marker, _LINE_COMMENT, "\n"))
    for opener, closer in syntax.block_comments:
        tokens.append((opener, _BLOCK_COMMENT, closer))
    for delimiter in syntax.quotes:
        tokens.append((delimiter, _QUOTE, delimiter))
    return tuple(tokens)


def _blank(size: int) -> str:
    return " " * size


def _skip_line_comment(source: str, index: int) -> Tuple[str, int]:
    end = source.find("\n", index)
    if end == -1:
        end = len(source)
    return _blank(end - index), end


def _skip_block_comment(source: str, index: int, opener: str, closer: str) -> Tuple[str, int]:
    end = source.find(closer, index + len(opener))
    if end == -1:
        end = len(source)
    else:
        end += len(closer)
    chunk = source[index:end]
    # Giữ lại các ký tự xuống dòng để số dòng phía sau không xê dịch.
    return "".join("\n" if char == "\n" else " " for char in chunk), end


def _skip_long_quote(source: str, index: int, delimiter: str) -> Tuple[str, int]:
    end = source.find(delimiter, index + len(delimiter))
    if end == -1:
        end = len(source)
    else:
        end += len(delimiter)
    chunk = source[index:end]
    return "".join("\n" if char == "\n" else " " for char in chunk), end


def _skip_quote(source: str, index: int, delimiter: str) -> Tuple[str, int]:
    """Chuỗi một dòng. Đóng ở `delimiter`, ở cuối dòng, hoặc ở cuối tệp."""
    cursor = index + len(delimiter)
    limit = len(source)
    while cursor < limit:
        char = source[cursor]
        if char == "\\" and cursor + 1 < limit and source[cursor + 1] != "\n":
            cursor += 2
            continue
        if char == "\n":
            break
        if source.startswith(delimiter, cursor):
            cursor += len(delimiter)
            break
        cursor += 1
    return _blank(cursor - index), cursor


_TOKENS: Dict[str, Tuple[_Token, ...]] = {
    language: _build_tokens(syntax) for language, syntax in _SYNTAX.items()
}


def supports(language: str) -> bool:
    return language in _SYNTAX


def scrub(source: str, language: str) -> str:
    """Bản sao của `source` với chuỗi và chú thích thay bằng dấu cách.

    Nhảy giữa các chỗ "đáng quan tâm" bằng `str.find` rồi copy cả đoạn mã ở
    giữa bằng một phép cắt, thay vì duyệt từng ký tự. Bản đầu duyệt từng ký tự
    và tốn 117 micro giây mỗi KB, tức là một kho 100 MB phải trả thêm mười mấy
    giây cho riêng phép xóa này -- phần lớn chi phí nằm ở chỗ dựng một danh
    sách dài bằng số ký tự của tệp, chứ không ở phép so.

    Vị trí kế tiếp của từng token được nhớ lại và chỉ tìm lại khi con trỏ đã
    đi qua nó, nên mỗi token quét toàn tệp đúng một lượt: tổng chi phí tuyến
    tính theo độ dài tệp, không phải theo số chuỗi nhân số token.

    Trả về chính `source` khi không biết cú pháp của ngôn ngữ: thà dò trên văn
    bản thô và chịu rủi ro báo nhầm chỗ nhắc tới dấu hiệu, còn hơn im lặng xóa
    sai phần mã và hóa mù trước một webshell thật.
    """
    tokens = _TOKENS.get(language)
    if tokens is None:
        return source

    limit = len(source)
    positions = [source.find(token[0]) for token in tokens]
    pieces = []
    index = 0
    while index < limit:
        best_position = -1
        best_index = -1
        for order, token in enumerate(tokens):
            position = positions[order]
            if position != -1 and position < index:
                position = source.find(token[0], index)
                positions[order] = position
            if position == -1:
                continue
            if best_position == -1 or position < best_position:
                best_position = position
                best_index = order
        if best_position == -1:
            pieces.append(source[index:])
            break

        if best_position > index:
            pieces.append(source[index:best_position])
        opener, kind, closer = tokens[best_index]
        if kind == _LONG_QUOTE:
            chunk, index = _skip_long_quote(source, best_position, opener)
        elif kind == _LINE_COMMENT:
            chunk, index = _skip_line_comment(source, best_position)
        elif kind == _BLOCK_COMMENT:
            chunk, index = _skip_block_comment(source, best_position, opener, closer)
        else:
            chunk, index = _skip_quote(source, best_position, opener)
        pieces.append(chunk)

    scrubbed = "".join(pieces)
    # Phép khẳng định nội bộ: lệch độ dài nghĩa là mọi vị trí báo ra sau đây
    # đều sai, và sai âm thầm. Rơi về văn bản thô thì bộ dò kém chính xác hơn
    # nhưng không nói dối về vị trí.
    if len(scrubbed) != len(source):
        return source
    return scrubbed
