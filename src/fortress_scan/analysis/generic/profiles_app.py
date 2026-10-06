"""Ngôn ngữ ứng dụng thêm sau: Kotlin, Scala, Groovy, Swift, Dart, ...

Dùng chung bộ phân tích token với các ngôn ngữ trong profiles.py; tệp này chỉ
khai bảng nguồn, sink và bộ khử độc của từng ngôn ngữ.
"""

from __future__ import annotations

from typing import Dict

from .profiles import LanguageSpec

APPLICATION_SPECS: Dict[str, LanguageSpec] = {}
