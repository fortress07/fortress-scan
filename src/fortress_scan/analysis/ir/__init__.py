"""Truy vết xâm nhập: tìm thứ kẻ tấn công ĐỂ LẠI, không phải thứ lập trình viên viết sai.

Phần còn lại của công cụ trả lời "mã này có lỗ hổng không". Mô-đun này trả lời
một câu khác hẳn: "đã có người vào đây rồi chưa, và họ cắm lại cái gì". Hai câu
hỏi nhìn vào cùng một cây mã nhưng cần hai mô hình khác nhau, nên chúng không
dùng chung bộ dò.

Khác biệt cốt lõi là ĐƠN VỊ KẾT LUẬN. Một lời gọi ``eval($_POST['x'])`` nằm
trong một controller dài hai nghìn dòng là một lỗ hổng injection, và
FSB-EXEC-001 đã bắt nó. Cũng đúng lời gọi đó, nằm một mình trong một tệp bốn
dòng dưới ``uploads/``, mở đầu bằng ``@error_reporting(0)``, là một webshell
đã được cắm -- một sự việc đã xảy ra, không phải một rủi ro. Phân biệt được
hai thứ đó chỉ có cách nhìn CẢ TỆP, nên bộ dò ở đây tính điểm theo trụ trên
toàn tệp thay vì bắn theo từng dòng khớp mẫu.

Hệ quả cố ý: khi chỉ có "nguồn tới sink" mà không có dấu hiệu cắm ghép nào,
mô-đun này IM LẶNG và nhường cho các rule injection. Báo lại cùng một dòng
dưới cái tên "webshell" là nói sai về bản chất sự việc, và trong một ca ứng
cứu thì nói sai chỗ đó khiến người ta đi truy một vụ xâm nhập không có thật.
"""

from __future__ import annotations

from .analyzer import IRAnalyzer

__all__ = ["IRAnalyzer"]
