"""Phân tích xuyên file cho các ngôn ngữ đi qua bộ lexer chung.

Python có bộ phân tích AST riêng và chỉ mục riêng ( analysis/python/project ).
Gói này làm cùng việc đó cho JavaScript/TypeScript, Java/JVM và Go: tách hàm
ra khỏi dòng token, phân giải import / re-export / alias / kiểu của biến để
biết một lời gọi trỏ về hàm nào, rồi áp summary của hàm đó tại lời gọi.

Nó cũng đi theo những luồng rời khỏi mã nguồn: template được render, mapper
SQL dạng XML, hằng số SQL nằm trong tệp cấu hình hay module khác, tên hàng đợi
nối nơi gửi job với nơi xử lý job.
"""
