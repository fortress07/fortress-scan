from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from ...core.budget import Budget

IDENT = "ident"
STRING = "string"
NUMBER = "number"
OP = "op"
NEWLINE = "newline"

_MAX_INTERPOLATION_DEPTH = 4
_MAX_STRING_LENGTH = 4096


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    line: int
    column: int
    in_string: bool = False
    interpolated: bool = False
    quote: str = ""


@dataclass(frozen=True)
class LexerProfile:
    line_comments: Tuple[str, ...] = ("//",)
    block_comments: Tuple[Tuple[str, str], ...] = (("/*", "*/"),)
    plain_quotes: Tuple[str, ...] = ("'",)
    interpolating_quotes: Tuple[str, ...] = ('"',)
    interpolation_markers: Tuple[Tuple[str, str], ...] = (("${", "}"),)
    dollar_interpolation: bool = False
    identifier_extra: str = "_$"
    heredoc_markers: Tuple[str, ...] = ()
    # Nhãn heredoc TRẦN phải dính liền dấu mở. Đúng với Perl và PHP; shell thì
    # `cat << EOF` có khoảng trắng vẫn là heredoc thật, nên cờ này tắt ở đó.
    heredoc_bare_adjacent: bool = False
    escape_character: str = "\\"
    raw_quotes: Tuple[str, ...] = ()
    # Chuỗi ba nháy ( Kotlin, Scala, Groovy, Swift, Dart, Julia, Elixir ): một
    # dấu `"` đơn lẻ bên trong không đóng chuỗi. ( dấu mở, có nội suy không ).
    triple_quotes: Tuple[Tuple[str, bool], ...] = ()
    # VB.NET: `""` trong chuỗi là một dấu nháy, không phải đóng rồi mở lại.
    doubled_quote_escape: bool = False
    # Kotlin, Groovy, Dart, Scala: `"$host"` nhắc tới biến `host`, không phải
    # `$host` như shell hay PHP. Chữ số sau `$` ở đó là chữ thường, không nội suy.
    dollar_bare_name: bool = False
    # Tiền tố dính liền dấu nháy quyết định chuỗi có nội suy không: `s"..."` của
    # Scala nội suy, `sql"..."` của Slick/doobie thì biến các giá trị thành tham
    # số bind. ( tiền tố, có nội suy không ).
    string_prefixes: Tuple[Tuple[str, bool], ...] = ()
    # Scala: chuỗi không có tiền tố thì `$x` chỉ là chữ.
    prefix_only_interpolation: bool = False
    multichar_operators: Tuple[str, ...] = (
        "===",
        "!==",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "=>",
        "->",
        "::",
        "+=",
        "-=",
        "*=",
        "/=",
        ".=",
        "??",
        "?.",
        "**",
        "<<",
        ">>",
    )


def _is_identifier_start(char: str, profile: LexerProfile) -> bool:
    return char.isalpha() or char in profile.identifier_extra or ord(char) > 127


def _is_identifier_part(char: str, profile: LexerProfile) -> bool:
    return char.isalnum() or char in profile.identifier_extra or ord(char) > 127


class Tokenizer:
    def __init__(
        self, source: str, profile: LexerProfile, budget: Budget, depth: int = 0
    ) -> None:
        self._source = source
        self._profile = profile
        self._budget = budget
        self._depth = depth
        self._length = len(source)
        self._index = 0
        self._line = 1
        # Cột đếm từ 0, ĐÚNG như ast.col_offset của bộ phân tích Python. Cả
        # đường ra phía sau ( console, JSON, SARIF startColumn = column + 1 )
        # đều giả định 0-based; đếm từ 1 ở đây khiến MỌI phát hiện của mọi ngôn
        # ngữ dùng lexer này lệch một cột, và trên GitHub code scanning là tô
        # sai một ký tự so với lời gọi thật.
        self._column = 0
        self._tokens: List[Token] = []

    def run(self) -> List[Token]:
        while self._index < self._length:
            self._budget.spend()
            char = self._source[self._index]
            if char == "\n":
                self._emit(NEWLINE, "\n")
                self._advance(1)
                self._line += 1
                self._column = 0
                continue
            if char in " \t\r\f\v":
                self._advance(1)
                continue
            if self._skip_comment():
                continue
            if self._read_heredoc():
                continue
            if self._read_triple_string():
                continue
            if self._read_string():
                continue
            if char.isdigit():
                self._read_number()
                continue
            if _is_identifier_start(char, self._profile):
                self._read_identifier()
                continue
            self._read_operator()
        return self._tokens

    def _emit(self, kind: str, text: str, in_string: bool = False, quote: str = "") -> None:
        self._tokens.append(
            Token(
                kind=kind,
                text=text,
                line=self._line,
                column=self._column,
                in_string=in_string,
                quote=quote,
            )
        )

    def _advance(self, count: int) -> None:
        self._index += count
        self._column += count

    def _advance_over(self, segment: str) -> None:
        """Đi hết một đoạn đã đọc nguyên khối ( chuỗi, heredoc, chú thích khối ).

        Các đoạn này trước đây đặt thẳng column về đầu dòng. Đúng khi đoạn có
        xuống dòng, nhưng SAI hẳn khi nó nằm gọn trong một dòng: sau
        `$log = "prefix"; system($x)` thì `system` bị báo ở cột 2 thay vì 17 -
        mọi token đứng sau một chuỗi trên cùng dòng đều lệch, và đó là hình
        dạng phổ biến nhất của mã thật.
        """
        newlines = segment.count("\n")
        if newlines:
            self._line += newlines
            self._column = len(segment) - segment.rfind("\n") - 1
        else:
            self._column += len(segment)

    def _skip_comment(self) -> bool:
        for marker in self._profile.line_comments:
            if self._source.startswith(marker, self._index):
                end = self._source.find("\n", self._index)
                if end == -1:
                    self._index = self._length
                else:
                    self._advance(end - self._index)
                return True
        for opener, closer in self._profile.block_comments:
            if self._source.startswith(opener, self._index):
                end = self._source.find(closer, self._index + len(opener))
                segment_end = self._length if end == -1 else end + len(closer)
                segment = self._source[self._index : segment_end]
                self._index = segment_end
                self._advance_over(segment)
                return True
        return False

    def _read_heredoc(self) -> bool:
        for marker in self._profile.heredoc_markers:
            if not self._source.startswith(marker, self._index):
                continue
            cursor = self._index + len(marker)
            padded = False
            while cursor < self._length and self._source[cursor] in " \t~-":
                padded = True
                cursor += 1
            quote = ""
            if cursor < self._length and self._source[cursor] in "\"'":
                quote = self._source[cursor]
                cursor += 1
            start = cursor
            while cursor < self._length and (
                self._source[cursor].isalnum() or self._source[cursor] == "_"
            ):
                cursor += 1
            label = self._source[start:cursor]
            if not self._is_heredoc_label(label, quote, padded):
                return False
            if quote and cursor < self._length and self._source[cursor] == quote:
                cursor += 1
            body_start = self._source.find("\n", cursor)
            if body_start == -1:
                return False
            body_start += 1
            terminator = self._find_heredoc_end(label, body_start)
            body = self._source[body_start:terminator][:_MAX_STRING_LENGTH]
            segment = self._source[self._index : terminator]
            self._emit(STRING, body, in_string=False)
            if quote != "'":
                self._scan_interpolations(body)
            self._index = terminator
            self._advance_over(segment)
            return True
        return False

    def _is_heredoc_label(self, label: str, quote: str, padded: bool) -> bool:
        """Chuỗi vừa đọc có đúng là nhãn heredoc không.

        `<<` còn là toán tử dịch trái, và nhận nhầm nó là mở heredoc thì phần
        còn lại của TỆP bị nuốt vào một chuỗi không bao giờ đóng. Mọi phát hiện
        phía sau biến mất, không lỗi, không dấu vết. Một dòng `my $mask = 1 << 8;`
        là đủ để làm điều đó với cả tệp Perl.

        Hai luật, và cả hai đều lấy từ chính cú pháp của các ngôn ngữ này:
        nhãn là một định danh nên không mở đầu bằng chữ số; và ở Perl nhãn
        trần phải dính liền `<<`, có khoảng trắng là phép dịch trái.
        """
        if not label or label[0].isdigit():
            return False
        if padded and not quote and self._profile.heredoc_bare_adjacent:
            return False
        return True

    def _find_heredoc_end(self, label: str, start: int) -> int:
        cursor = start
        while cursor < self._length:
            end_of_line = self._source.find("\n", cursor)
            if end_of_line == -1:
                end_of_line = self._length
            if self._source[cursor:end_of_line].strip().rstrip(";") == label:
                return cursor
            cursor = end_of_line + 1
        return self._length

    def _prefix_interpolates(self, default: bool) -> Tuple[bool, bool]:
        """`s"..."` / `sql"..."`: tiền tố dính liền dấu nháy quyết định nội suy.

        Trả về ( cú pháp có vùng nội suy không, có phát token nội suy không ).
        `sql"... ${id}"` vẫn có vùng `${}` phải nhảy qua, chỉ là giá trị trong đó
        thành tham số bind chứ không dán vào chuỗi.

        Token tiền tố bị bỏ khỏi luồng: nó là một phần của literal, để lại thì
        `s"SELECT 1"` trông như một biểu thức có tên biến chứ không phải hằng.
        """
        profile = self._profile
        if not profile.string_prefixes:
            return default, default
        if self._tokens:
            last = self._tokens[-1]
            if (
                not last.in_string
                and last.kind in (IDENT, OP)
                and last.line == self._line
                and last.column + len(last.text) == self._column
            ):
                for prefix, interpolating in profile.string_prefixes:
                    if last.text == prefix:
                        self._tokens.pop()
                        return default, default and interpolating
        plain = default and not profile.prefix_only_interpolation
        return plain, plain

    def _read_triple_string(self) -> bool:
        for opener, interpolating in self._profile.triple_quotes:
            if not self._source.startswith(opener, self._index):
                continue
            _, interpolating = self._prefix_interpolates(interpolating)
            end = self._source.find(opener, self._index + len(opener))
            stop = self._length if end == -1 else end + len(opener)
            # Swift/Kotlin cho phép thêm nháy sát dấu đóng: `""""a""""`.
            while stop < self._length and self._source[stop] == opener[0] and end != -1:
                stop += 1
            body_end = self._length if end == -1 else stop - len(opener)
            body = self._source[self._index + len(opener) : body_end][:_MAX_STRING_LENGTH]
            segment = self._source[self._index : stop]
            self._emit(STRING, body, quote=opener[0])
            if interpolating:
                self._scan_interpolations(body)
            self._index = stop
            self._advance_over(segment)
            return True
        return False

    def _read_string(self) -> bool:
        char = self._source[self._index]
        profile = self._profile
        if char not in profile.plain_quotes and char not in profile.interpolating_quotes:
            if char not in profile.raw_quotes:
                return False
        interpolating = char in profile.interpolating_quotes
        emit = interpolating
        if interpolating:
            interpolating, emit = self._prefix_interpolates(True)
        raw = char in profile.raw_quotes
        cursor = self._index + 1
        pieces: List[str] = []
        while cursor < self._length:
            current = self._source[cursor]
            if interpolating and not raw:
                # Vùng nội suy là mã, nên nó có thể chứa một chuỗi lồng dùng
                # đúng dấu nháy đang mở: `outer ${`inner`} end`. Nhảy qua trọn
                # vùng đó, nếu không thì dấu nháy mở của chuỗi lồng bị hiểu là
                # dấu đóng của chuỗi ngoài, và phần ruột chuỗi rơi ra ngoài
                # thành mã. Kiểm TRƯỚC ký tự thoát: dấu mở `\(` của Swift bắt
                # đầu bằng chính ký tự thoát.
                span = self._interpolation_span(cursor)
                if span != -1:
                    pieces.append(self._source[cursor:span])
                    cursor = span
                    continue
            if not raw and current == profile.escape_character and cursor + 1 < self._length:
                pieces.append(self._source[cursor + 1])
                cursor += 2
                continue
            if (
                profile.doubled_quote_escape
                and current == char
                and cursor + 1 < self._length
                and self._source[cursor + 1] == char
            ):
                pieces.append(char)
                cursor += 2
                continue
            if current == char:
                cursor += 1
                break
            pieces.append(current)
            cursor += 1
        body = "".join(pieces)[:_MAX_STRING_LENGTH]
        segment = self._source[self._index : cursor]
        self._emit(STRING, body, quote=char)
        if emit and not raw:
            self._scan_interpolations(body)
        self._index = cursor
        self._advance_over(segment)
        return True

    def _skip_quoted(self, index: int) -> int:
        """Bỏ qua một chuỗi lồng nằm bên trong vùng nội suy."""
        quote = self._source[index]
        cursor = index + 1
        escape = self._profile.escape_character
        while cursor < self._length:
            char = self._source[cursor]
            if char == escape and cursor + 1 < self._length:
                cursor += 2
                continue
            if char == quote:
                return cursor + 1
            cursor += 1
        return cursor

    def _interpolation_span(self, index: int) -> int:
        """Chỉ số ngay sau dấu đóng khớp của vùng nội suy bắt đầu tại index.

        Trả về -1 nếu ở đây không mở vùng nội suy nào, hoặc vùng đó không đóng
        lại -- khi đó phần còn lại được đọc như thân chuỗi bình thường.
        """
        profile = self._profile
        quotes = (
            tuple(profile.plain_quotes)
            + tuple(profile.interpolating_quotes)
            + tuple(profile.raw_quotes)
        )
        for opener, closer in profile.interpolation_markers:
            if self._source.startswith(opener, index):
                return self._scan_to_closer(index + len(opener), opener, closer, quotes)
        return -1

    def _scan_to_closer(
        self, cursor: int, opener: str, closer: str, quotes: Tuple[str, ...]
    ) -> int:
        depth = 1
        escape = self._profile.escape_character
        while cursor < self._length:
            self._budget.spend()
            char = self._source[cursor]
            if char == escape and cursor + 1 < self._length:
                cursor += 2
                continue
            if char in quotes:
                cursor = self._skip_quoted(cursor)
                continue
            if self._source.startswith(opener, cursor):
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

    def _scan_interpolations(self, body: str) -> None:
        if self._depth >= _MAX_INTERPOLATION_DEPTH:
            return
        profile = self._profile
        for opener, closer in profile.interpolation_markers:
            start = 0
            while True:
                position = body.find(opener, start)
                if position == -1:
                    break
                end = _matching_index(body, position + len(opener), opener[-1], closer)
                if end == -1:
                    break
                inner = body[position + len(opener) : end]
                self._emit_inner(inner)
                start = end + len(closer)
        if profile.dollar_interpolation:
            self._scan_dollar(body)

    def _scan_dollar(self, body: str) -> None:
        profile = self._profile
        index = 0
        length = len(body)
        while index < length:
            position = body.find("$", index)
            if position == -1 or position + 1 >= length:
                return
            following = body[position + 1]
            if following == "{":
                if profile.dollar_bare_name:
                    end = _matching_index(body, position + 2, "{", "}")
                else:
                    end = body.find("}", position + 2)
                if end == -1:
                    return
                # `${...}` đã được phát ở vòng interpolation_markers nếu có khai.
                if ("${", "}") not in profile.interpolation_markers:
                    self._emit_inner(body[position + 2 : end])
                index = end + 1
                continue
            if following == "(":
                end = _matching_index(body, position + 2, "(", ")")
                if end == -1:
                    return
                self._emit_inner(body[position + 2 : end])
                index = end + 1
                continue
            if following.isdigit() or following in "@*#?":
                if not profile.dollar_bare_name:
                    self._emit_expansion(body[position : position + 2])
                index = position + 2
                continue
            if _is_identifier_start(following, self._profile) and not (profile.dollar_bare_name and following == "$"):
                cursor = position + 1
                while cursor < length and _is_identifier_part(body[cursor], self._profile):
                    cursor += 1
                start = position + 1 if profile.dollar_bare_name else position
                self._emit_expansion(body[start:cursor])
                index = cursor
                continue
            index = position + 1

    def _emit_expansion(self, text: str) -> None:
        self._tokens.append(
            Token(
                kind=IDENT,
                text=text,
                line=self._line,
                column=self._column,
                in_string=True,
                interpolated=True,
            )
        )

    def _emit_inner(self, inner: str) -> None:
        if not inner.strip():
            return
        nested = Tokenizer(inner, self._profile, self._budget, self._depth + 1)
        nested._line = self._line
        nested._column = self._column
        for token in nested.run():
            if token.kind == NEWLINE:
                continue
            self._tokens.append(
                Token(
                    kind=token.kind,
                    text=token.text,
                    line=self._line,
                    column=self._column,
                    in_string=True,
                    interpolated=True,
                )
            )

    def _read_number(self) -> None:
        cursor = self._index
        while cursor < self._length and (
            self._source[cursor].isalnum() or self._source[cursor] in "._"
        ):
            cursor += 1
        self._emit(NUMBER, self._source[self._index : cursor])
        self._advance(cursor - self._index)

    def _read_identifier(self) -> None:
        cursor = self._index
        while cursor < self._length and _is_identifier_part(self._source[cursor], self._profile):
            cursor += 1
        self._emit(IDENT, self._source[self._index : cursor])
        self._advance(cursor - self._index)

    def _read_operator(self) -> None:
        for operator in self._profile.multichar_operators:
            if self._source.startswith(operator, self._index):
                self._emit(OP, operator)
                self._advance(len(operator))
                return
        self._emit(OP, self._source[self._index])
        self._advance(1)


def _matching_index(text: str, start: int, opener: str, closer: str) -> int:
    depth = 1
    index = start
    length = len(text)
    while index < length:
        char = text[index]
        if char == opener and opener != closer:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def tokenize(source: str, profile: LexerProfile, budget: Budget) -> List[Token]:
    return Tokenizer(source, profile, budget).run()
