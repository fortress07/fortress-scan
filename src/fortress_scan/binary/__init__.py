"""Phân tích tĩnh tệp thực thi để tìm dấu hiệu ransomware ( beta ).

Chỉ đọc tệp. Không thực thi, không nạp, không giải nén ra đĩa, không gửi gì
ra mạng. Xem README mục "Phân tích file thực thi tìm ransomware".
"""

from __future__ import annotations

from .engine import analyze_bytes, analyze_path, discover
from .model import TriageReport, Verdict

__all__ = ["TriageReport", "Verdict", "analyze_bytes", "analyze_path", "discover"]
