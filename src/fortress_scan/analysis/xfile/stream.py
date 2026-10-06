"""Tiện ích đi trên dòng token: ghép ngoặc, bỏ qua dòng trống, đọc chuỗi truy cập."""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from ..generic.lexer import IDENT, NEWLINE, OP, STRING, Token

_OPENERS = {"(": ")", "[": "]", "{": "}"}
_CLOSERS = {")": "(", "]": "[", "}": "{"}


class Stream:
    """Dòng token kèm bảng ghép ngoặc, đọc được theo vị trí."""

    def __init__(self, tokens: Sequence[Token]) -> None:
        self.tokens = tokens
        self.size = len(tokens)
        self.match: List[int] = [-1] * self.size
        # Ngoặc nhọn bao trực tiếp từng token: -1 nghĩa là cấp module.
        self.parent: List[int] = [-1] * self.size
        stack: List[Tuple[str, int]] = []
        braces: List[int] = []
        for index, token in enumerate(tokens):
            self.parent[index] = braces[-1] if braces else -1
            if token.kind != OP or token.in_string:
                continue
            text = token.text
            if text in _OPENERS:
                stack.append((text, index))
                if text == "{":
                    braces.append(index)
            elif text in _CLOSERS:
                wanted = _CLOSERS[text]
                # Ngoặc lệch ( mã hỏng, macro ) không được làm sập cả tệp:
                # tìm ngược tới ngoặc mở cùng loại, bỏ những cái bị bỏ quên.
                for depth in range(len(stack) - 1, -1, -1):
                    if stack[depth][0] == wanted:
                        opener = stack[depth][1]
                        for _, dropped in stack[depth + 1 :]:
                            if tokens[dropped].text == "{" and braces and braces[-1] == dropped:
                                braces.pop()
                        del stack[depth:]
                        self.match[opener] = index
                        self.match[index] = opener
                        if wanted == "{" and braces and braces[-1] == opener:
                            braces.pop()
                        break

    def sig(self, index: int) -> int:
        """Vị trí token có nghĩa đầu tiên kể từ `index` ( bỏ dòng mới )."""
        while index < self.size and self.tokens[index].kind == NEWLINE:
            index += 1
        return index

    def back(self, index: int) -> int:
        """Vị trí token có nghĩa gần nhất về phía trước, tính cả `index`."""
        while index >= 0 and self.tokens[index].kind == NEWLINE:
            index -= 1
        return index

    def is_op(self, index: int, *texts: str) -> bool:
        if not 0 <= index < self.size:
            return False
        token = self.tokens[index]
        return token.kind == OP and not token.in_string and token.text in texts

    def is_ident(self, index: int, *texts: str) -> bool:
        if not 0 <= index < self.size:
            return False
        token = self.tokens[index]
        if token.kind != IDENT or token.in_string:
            return False
        return not texts or token.text in texts

    def is_string(self, index: int) -> bool:
        return 0 <= index < self.size and self.tokens[index].kind == STRING

    def text(self, index: int) -> str:
        return self.tokens[index].text if 0 <= index < self.size else ""

    def closing(self, index: int) -> int:
        """Vị trí ngoặc đóng của ngoặc mở tại `index`, hoặc -1."""
        if not 0 <= index < self.size:
            return -1
        found = self.match[index]
        return found if found > index else -1

    def chain_at(self, index: int, separators: Tuple[str, ...] = (".",)) -> Tuple[Optional[str], int]:
        """Đọc `a.b.c` bắt đầu tại `index`; trả về (chuỗi, vị trí sau nó)."""
        if not self.is_ident(index):
            return None, index
        parts = [self.tokens[index].text]
        cursor = index + 1
        while cursor + 1 < self.size:
            if not self.is_op(cursor, *separators):
                break
            # `a?.b` cũng là truy cập thuộc tính.
            if not self.is_ident(cursor + 1):
                break
            parts.append(self.tokens[cursor + 1].text)
            cursor += 2
        return ".".join(parts), cursor

    def chain_ending(self, index: int, separators: Tuple[str, ...] = (".",)) -> Tuple[Optional[str], int]:
        """Đọc ngược chuỗi truy cập kết thúc tại `index`; trả về (chuỗi, vị trí đầu)."""
        if not self.is_ident(index):
            return None, index
        parts = [self.tokens[index].text]
        cursor = index
        while cursor - 2 >= 0 and self.is_op(cursor - 1, *separators) and self.is_ident(cursor - 2):
            parts.append(self.tokens[cursor - 2].text)
            cursor -= 2
        parts.reverse()
        return ".".join(parts), cursor

    def string_value(self, start: int, end: int) -> Optional[str]:
        """Giá trị của một biểu thức chỉ gồm chuỗi hằng nối bằng `+`."""
        pieces: List[str] = []
        expect_string = True
        for index in range(start, end):
            token = self.tokens[index]
            if token.kind == NEWLINE:
                continue
            if token.in_string or token.interpolated:
                return None
            if expect_string:
                if token.kind != STRING:
                    return None
                pieces.append(token.text)
                expect_string = False
            else:
                if token.kind != OP or token.text != "+":
                    return None
                expect_string = True
        if expect_string or not pieces:
            return None
        return "".join(pieces)

    def split_commas(self, start: int, end: int) -> List[Tuple[int, int]]:
        """Chia đoạn [start, end) theo dấu phẩy ở cấp ngoặc ngoài cùng."""
        pieces: List[Tuple[int, int]] = []
        cursor = start
        piece_start = start
        while cursor < end:
            token = self.tokens[cursor]
            if token.kind == OP and not token.in_string:
                if token.text in _OPENERS:
                    closing = self.closing(cursor)
                    if closing > cursor and closing < end:
                        cursor = closing + 1
                        continue
                elif token.text == ",":
                    pieces.append((piece_start, cursor))
                    piece_start = cursor + 1
                elif token.text == "<":
                    # Kiểu generic `Map<String, Integer>` không được chia đôi.
                    skipped = self.skip_generic(cursor, end)
                    if skipped > cursor:
                        cursor = skipped
                        continue
            cursor += 1
        if piece_start < end:
            pieces.append((piece_start, end))
        return [
            (a, b)
            for a, b in pieces
            if any(self.tokens[i].kind != NEWLINE for i in range(a, b))
        ]

    def skip_generic(self, index: int, limit: int) -> int:
        """Vị trí ngay sau `<...>` nếu đó là danh sách kiểu, ngược lại `index`."""
        if not self.is_op(index, "<"):
            return index
        depth = 0
        cursor = index
        while cursor < limit and cursor - index < 64:
            token = self.tokens[cursor]
            if token.kind == OP and not token.in_string:
                if token.text == "<":
                    depth += 1
                elif token.text == ">":
                    depth -= 1
                    if depth == 0:
                        return cursor + 1
                elif token.text == ">>":
                    depth -= 2
                    if depth <= 0:
                        return cursor + 1
                elif token.text not in (",", ".", "?", "[", "]", "&", "|", "*"):
                    return index
            elif token.kind not in (IDENT, NEWLINE):
                return index
            cursor += 1
        return index

    def idents(self, start: int, end: int) -> List[int]:
        return [i for i in range(start, end) if self.is_ident(i)]


# Khối mà thân của nó có thể KHÔNG chạy: gán lại bên trong không xóa được vết
# nhiễm đã có từ trước khối, vì nhánh còn lại vẫn mang giá trị cũ đi tiếp.
_CONDITIONAL_HEADS = frozenset(
    {"if", "else", "elif", "for", "foreach", "while", "switch", "case", "catch", "select", "unless", "until", "except"}
)


class TokenIndex:
    """Vị trí token trong tệp và những khối điều kiện bao quanh nó."""

    def __init__(self, tokens: Sequence[Token]) -> None:
        self.tokens = tokens
        self.positions: dict = {}
        for index, token in enumerate(tokens):
            if token.kind == NEWLINE:
                continue
            self.positions.setdefault((token.line, token.column), index)
        self._stream: Optional[Stream] = None
        self._conditional: Optional[dict] = None

    @property
    def stream(self) -> Stream:
        if self._stream is None:
            self._stream = Stream(self.tokens)
        return self._stream

    def index_of(self, token: Token) -> Optional[int]:
        return self.positions.get((token.line, token.column))

    def _brace_is_conditional(self, brace: int) -> bool:
        stream = self.stream
        cursor = brace - 1
        first = ""
        texts = []
        steps = 0
        while cursor >= 0 and steps < 96:
            steps += 1
            token = self.tokens[cursor]
            if token.kind == NEWLINE:
                # Ngôn ngữ không cần ngoặc quanh điều kiện ( Go ): đầu khối
                # nằm gọn trên một dòng.
                if texts and not stream.is_op(cursor - 1, "(", ",", "&&", "||", "+", "."):
                    break
                cursor -= 1
                continue
            if token.kind == OP and not token.in_string:
                if token.text in (";", "{", "}"):
                    break
                if token.text in (")", "]"):
                    opener = stream.match[cursor]
                    if 0 <= opener < cursor:
                        cursor = opener - 1
                        texts.append(token.text)
                        continue
            if token.kind == IDENT and not token.in_string:
                first = token.text
                texts.append(token.text)
            else:
                texts.append(token.text)
            cursor -= 1
        return first in _CONDITIONAL_HEADS or "else" in texts

    def conditional(self, token: Token) -> bool:
        index = self.index_of(token)
        if index is None:
            return False
        if self._conditional is None:
            self._conditional = {}
        brace = self.stream.parent[index]
        while brace >= 0:
            known = self._conditional.get(brace)
            if known is None:
                known = self._brace_is_conditional(brace)
                self._conditional[brace] = known
            if known:
                return True
            brace = self.stream.parent[brace]
        return False
