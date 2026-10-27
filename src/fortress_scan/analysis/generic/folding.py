"""Gập hằng cho điều kiện rẽ nhánh: biết trước nhánh nào chết.

    int num = 86;
    if ((7 * 42) - num > 200) bar = "safe"; else bar = param;   // nhánh else chạy
    bar = (7 * 18) + num > 200 ? "safe" : param;               // vế sau chạy
    switch ("ABC".charAt(1)) { case 'A': bar = param; break; case 'B': ... }

Chỉ hiểu số nguyên, chuỗi, ký tự, so sánh, `&&`/`||`/`!`, `+ - * / %`, và vài
phương thức chuỗi thuần ( charAt, length, equals, substring ). Gặp thứ gì khác
thì trả None: không biết thì không đoán, nhánh nào cũng được coi là sống.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Union

from .lexer import IDENT, NEWLINE, NUMBER, OP, STRING, Token

Value = Union[int, str, bool]

_MAX_TOKENS = 96
_MAX_STRING = 256


class _Unknown(Exception):
    pass


def fold(tokens: Sequence[Token], env: Dict[str, Value]) -> Optional[Value]:
    significant = [token for token in tokens if token.kind != NEWLINE]
    if not significant or len(significant) > _MAX_TOKENS:
        return None
    parser = _Parser(significant, env)
    try:
        value = parser.ternary()
    except (_Unknown, RecursionError, ZeroDivisionError):
        return None
    if parser.position != len(significant):
        return None
    return value


def truth(value: Optional[Value]) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    return None


class _Parser:
    def __init__(self, tokens: List[Token], env: Dict[str, Value]) -> None:
        self.tokens = tokens
        self.env = env
        self.position = 0

    # ---------------------------------------------------------- helpers
    def _peek(self, *texts: str) -> bool:
        if self.position >= len(self.tokens):
            return False
        token = self.tokens[self.position]
        return token.kind == OP and not token.in_string and token.text in texts

    def _take(self) -> Token:
        if self.position >= len(self.tokens):
            raise _Unknown()
        token = self.tokens[self.position]
        self.position += 1
        return token

    def _expect(self, text: str) -> None:
        if not self._peek(text):
            raise _Unknown()
        self.position += 1

    # ---------------------------------------------------------- grammar
    def ternary(self) -> Value:
        condition = self.logical_or()
        if self._peek("?"):
            self.position += 1
            yes = self.ternary()
            self._expect(":")
            no = self.ternary()
            decided = truth(condition)
            if decided is None:
                raise _Unknown()
            return yes if decided else no
        return condition

    def logical_or(self) -> Value:
        value = self.logical_and()
        while self._peek("||"):
            self.position += 1
            right = self.logical_and()
            left_truth, right_truth = truth(value), truth(right)
            if left_truth is None or right_truth is None:
                raise _Unknown()
            value = left_truth or right_truth
        return value

    def logical_and(self) -> Value:
        value = self.comparison()
        while self._peek("&&"):
            self.position += 1
            right = self.comparison()
            left_truth, right_truth = truth(value), truth(right)
            if left_truth is None or right_truth is None:
                raise _Unknown()
            value = left_truth and right_truth
        return value

    def comparison(self) -> Value:
        value = self.additive()
        while self._peek("==", "!=", "===", "!==", "<", ">", "<=", ">="):
            operator = self._take().text
            right = self.additive()
            value = _compare(operator, value, right)
        return value

    def additive(self) -> Value:
        value = self.multiplicative()
        while self._peek("+", "-"):
            operator = self._take().text
            right = self.multiplicative()
            if operator == "+" and (isinstance(value, str) or isinstance(right, str)):
                value = _text(value) + _text(right)
                if len(value) > _MAX_STRING:
                    raise _Unknown()
            else:
                value = _number(value) + _number(right) if operator == "+" else _number(value) - _number(right)
        return value

    def multiplicative(self) -> Value:
        value = self.unary()
        while self._peek("*", "/", "%"):
            operator = self._take().text
            right = _number(self.unary())
            left = _number(value)
            if operator == "*":
                value = left * right
            elif operator == "/":
                quotient = abs(left) // abs(right)
                value = quotient if (left >= 0) == (right >= 0) else -quotient
            else:
                value = left - right * int(left / right)
            if abs(value) > 1 << 62:
                raise _Unknown()
        return value

    def unary(self) -> Value:
        if self._peek("-"):
            self.position += 1
            return -_number(self.unary())
        if self._peek("!"):
            self.position += 1
            decided = truth(self.unary())
            if decided is None:
                raise _Unknown()
            return not decided
        return self.postfix()

    def postfix(self) -> Value:
        value = self.primary()
        while self._peek("."):
            self.position += 1
            method = self._take()
            if method.kind != IDENT:
                raise _Unknown()
            arguments = self._arguments()
            value = _call(value, method.text, arguments)
        return value

    def _arguments(self) -> List[Value]:
        self._expect("(")
        values: List[Value] = []
        if self._peek(")"):
            self.position += 1
            return values
        while True:
            values.append(self.ternary())
            if self._peek(","):
                self.position += 1
                continue
            self._expect(")")
            return values

    def primary(self) -> Value:
        token = self._take()
        if token.in_string or token.interpolated:
            raise _Unknown()
        if token.kind == NUMBER:
            text = token.text.rstrip("lLuU")
            if not text.isdigit():
                raise _Unknown()
            return int(text)
        if token.kind == STRING:
            if len(token.text) > _MAX_STRING:
                raise _Unknown()
            return token.text
        if token.kind == IDENT:
            if token.text == "true":
                return True
            if token.text == "false":
                return False
            if token.text in self.env:
                return self.env[token.text]
            raise _Unknown()
        if token.kind == OP and token.text == "(":
            # Ép kiểu `(int) x`, `(String) x`: bỏ qua phần kiểu.
            if (
                self.position + 1 < len(self.tokens)
                and self.tokens[self.position].kind == IDENT
                and self.tokens[self.position].text in ("int", "long", "short", "char", "String")
                and self.tokens[self.position + 1].kind == OP
                and self.tokens[self.position + 1].text == ")"
            ):
                self.position += 2
                return self.unary()
            value = self.ternary()
            self._expect(")")
            return value
        raise _Unknown()


def _number(value: Value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, str) and len(value) == 1:
            return ord(value)
        raise _Unknown()
    return value


def _text(value: Value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _compare(operator: str, left: Value, right: Value) -> bool:
    if operator in ("==", "===", "!=", "!=="):
        if type(left) is not type(right):
            if isinstance(left, str) and isinstance(right, int) and len(left) == 1:
                left = ord(left)
            elif isinstance(right, str) and isinstance(left, int) and len(right) == 1:
                right = ord(right)
            else:
                raise _Unknown()
        same = left == right
        return same if operator in ("==", "===") else not same
    a, b = _number(left), _number(right)
    if operator == "<":
        return a < b
    if operator == ">":
        return a > b
    if operator == "<=":
        return a <= b
    return a >= b


def _call(value: Value, method: str, arguments: List[Value]) -> Value:
    if not isinstance(value, str):
        raise _Unknown()
    if method == "charAt" and len(arguments) == 1:
        index = _number(arguments[0])
        if not 0 <= index < len(value):
            raise _Unknown()
        return value[index]
    if method == "length" and not arguments:
        return len(value)
    if method in ("equals", "contentEquals") and len(arguments) == 1:
        return isinstance(arguments[0], str) and value == arguments[0]
    if method == "substring" and 1 <= len(arguments) <= 2:
        start = _number(arguments[0])
        end = _number(arguments[1]) if len(arguments) == 2 else len(value)
        if not 0 <= start <= end <= len(value):
            raise _Unknown()
        return value[start:end]
    if method in ("toUpperCase", "toLowerCase", "trim") and not arguments:
        return value.upper() if method == "toUpperCase" else value.lower() if method == "toLowerCase" else value.strip()
    raise _Unknown()
