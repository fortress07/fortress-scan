"""Danh mục dấu hiệu ransomware mà bộ phân tích file thực thi biết.

Mỗi dấu hiệu nói rõ ba điều: vì sao nó đáng chú ý, phần mềm LÀNH nào cũng có
nó ( để người đọc tự cân ), và người phòng thủ nên làm gì. Mã kỹ thuật theo
MITRE ATT&CK ( Enterprise ). Kiến thức về dấu hiệu lấy từ tài liệu phòng thủ
công khai: các khuyến cáo #StopRansomware của CISA, MITRE ATT&CK và báo cáo
phân tích của các vendor bảo mật.
"""

from __future__ import annotations

from typing import Dict

from .model import IndicatorSpec, Tier

_C = Tier.CONTEXT
_S = Tier.SUSPICIOUS
_X = Tier.STRONG

_SPECS = (
    # ---------------------------------------------------------------- cấu trúc
    IndicatorSpec(
        "FSX-S01", "structural", _C, 2,
        "Tệp đã được pack hoặc bảo vệ bằng công cụ đã biết tên",
        "Packer nén hoặc mã hoá mã thật, nên phân tích tĩnh chỉ nhìn thấy lớp vỏ. "
        "Ransomware thường được pack để né chữ ký.",
        "Rất nhiều phần mềm hợp pháp dùng UPX, VMProtect hay Themida để giảm dung lượng hoặc chống crack.",
        "Coi mọi kết luận 'sạch' của tệp này là chưa đủ tin: giải nén ( ví dụ upx -d trên bản sao ) "
        "hoặc phân tích động trong sandbox cách ly trước khi cho phép chạy.",
        ("T1027.002",),
    ),
    IndicatorSpec(
        "FSX-S02", "structural", _C, 2,
        "Section chứa mã có entropy rất cao",
        "Mã máy bình thường có entropy khoảng 5.5 - 6.8 bit/byte; trên 7.2 thường nghĩa là "
        "mã đã bị nén hoặc mã hoá và sẽ được giải ra lúc chạy.",
        "Trình cài đặt, game và phần mềm có bảo vệ bản quyền cũng có section entropy cao.",
        "Không kết luận chỉ từ entropy. Kết hợp với các dấu hiệu năng lực bên dưới; nếu chỉ có "
        "dấu hiệu này thì phân tích động để thấy mã sau khi giải.",
        ("T1027.002",),
    ),
    IndicatorSpec(
        "FSX-S03", "structural", _S, 3,
        "Section / segment vừa ghi được vừa thực thi được ( W+X )",
        "Vùng nhớ W+X cho phép chương trình tự viết mã rồi chạy, kiểu điển hình của bộ giải "
        "nén và shellcode loader.",
        "Một số JIT, trình bảo vệ bản quyền và tệp biên dịch bằng toolchain cũ cũng có W+X.",
        "Ưu tiên phân tích động; bật DEP/ASLR bắt buộc trên máy trạm để giảm tác động.",
        ("T1027.002",),
    ),
    IndicatorSpec(
        "FSX-S04", "structural", _S, 3,
        "Bảng import nhỏ bất thường so với kích thước tệp",
        "Tệp lớn mà chỉ import vài hàm ( thường có LoadLibrary / GetProcAddress ) nghĩa là nó "
        "tự phân giải API lúc chạy để giấu năng lực thật khỏi phân tích tĩnh.",
        "Tệp viết bằng Go, Delphi hay liên kết tĩnh cũng có thể có ít import.",
        "Đừng dựa vào bảng import để đánh giá năng lực của tệp này; dùng phân tích động.",
        ("T1027.007", "T1106"),
    ),
    IndicatorSpec(
        "FSX-S05", "structural", _C, 2,
        "Dữ liệu entropy cao gắn sau phần cuối ảnh thực thi ( overlay )",
        "Overlay lớn và ngẫu nhiên có thể là payload mã hoá được bộ nạp giải ra lúc chạy.",
        "Trình cài đặt và kho tự giải nén ( NSIS, Inno Setup, 7-Zip SFX ) đều gắn payload nén vào overlay.",
        "Nếu tệp không tự nhận là trình cài đặt mà vẫn có overlay ngẫu nhiên lớn, xử lý nó như "
        "một bộ nạp và phân tích phần overlay riêng.",
        ("T1027.009",),
    ),
    IndicatorSpec(
        "FSX-S06", "structural", _C, 2,
        "Resource lớn có entropy cao",
        "Payload mã hoá giấu trong resource ( RCDATA ) là cách nhúng giai đoạn hai phổ biến.",
        "Ảnh, âm thanh nén và dữ liệu cài đặt cũng nằm trong resource với entropy cao.",
        "Trích resource ra phân tích riêng trong môi trường cách ly.",
        ("T1027.009",),
    ),
    IndicatorSpec(
        "FSX-S07", "structural", _S, 3,
        "Entry point nằm ở vị trí bất thường",
        "Entry point ngoài mọi section, hoặc trong section ghi được / không phải mã, là dấu "
        "hiệu của stub giải nén hoặc tệp bị can thiệp.",
        "Một số packer hợp pháp cũng đặt entry point như vậy.",
        "Phân tích động; so sánh với bản gốc của nhà phát hành nếu tệp tự nhận là phần mềm đã biết.",
        ("T1027.002",),
    ),
    IndicatorSpec(
        "FSX-S08", "structural", _C, 2,
        "Section thực thi rỗng trên đĩa nhưng lớn trong bộ nhớ",
        "Section có kích thước trên đĩa bằng 0 nhưng kích thước ảo lớn là chỗ bộ giải nén viết "
        "mã thật vào lúc chạy ( kiểu UPX0 ).",
        "Section .bss / dữ liệu chưa khởi tạo cũng như vậy, nhưng không mang cờ thực thi.",
        "Như FSX-S01: cần giải nén hoặc phân tích động.",
        ("T1027.002",),
    ),
    IndicatorSpec(
        "FSX-S09", "structural", _C, 1,
        "Tên section không in được hoặc rỗng",
        "Trình biên dịch chuẩn đặt tên section dễ đọc; tên rác thường do packer hoặc chỉnh tay.",
        "Một số trình biên dịch ít phổ biến cũng sinh tên lạ.",
        "Chỉ là bối cảnh; kết hợp với dấu hiệu khác.",
        ("T1027",),
    ),
    IndicatorSpec(
        "FSX-S10", "structural", _C, 1,
        "Dấu thời gian biên dịch bất thường",
        "Dấu thời gian bằng 0, ở tương lai hoặc trước năm 2000 thường do bị sửa để che nguồn gốc.",
        "Build tái lập ( reproducible build ) và Delphi cũ cũng đặt giá trị cố định hoặc lạ.",
        "Không dùng dấu thời gian để dựng dòng thời gian sự cố cho tệp này.",
        ("T1070.006",),
    ),
    IndicatorSpec(
        "FSX-S11", "structural", _S, 3,
        "Tự nhận là phần mềm của hãng lớn nhưng không có chữ ký số",
        "Thông tin phiên bản ghi tên hãng nổi tiếng mà tệp lại không ký là kiểu giả danh phổ biến.",
        "Bản build nội bộ hoặc công cụ cũ của chính hãng đôi khi không ký.",
        "Đối chiếu hash với bản phát hành chính thức của hãng; chặn chạy tệp không ký giả danh qua "
        "WDAC / AppLocker.",
        ("T1036.005",),
    ),
    IndicatorSpec(
        "FSX-S12", "structural", _C, 2,
        "Assembly .NET bị làm rối",
        "Obfuscator làm tên kiểu / phương thức không đọc được, giấu năng lực thật.",
        "Phần mềm thương mại .NET thường được obfuscate để chống dịch ngược.",
        "Dùng công cụ gỡ obfuscation trên bản sao trong môi trường cách ly trước khi kết luận.",
        ("T1027",),
    ),
    IndicatorSpec(
        "FSX-S13", "structural", _S, 3,
        "Script chứa payload được mã hoá / làm rối",
        "Lệnh PowerShell -EncodedCommand, chuỗi base64 + gzip được giải rồi chạy, hay nối chuỗi "
        "để giấu tên lệnh là kỹ thuật né phát hiện phổ biến của script độc hại.",
        "Một số script quản trị cũng dùng -EncodedCommand để tránh lỗi trích dẫn.",
        "Bật PowerShell Script Block Logging ( Event ID 4104 ) và AMSI để thấy nội dung đã giải mã "
        "khi chạy thật; báo cáo này đã giải các lớp tĩnh có thể giải.",
        ("T1027.010", "T1059.001"),
    ),
    IndicatorSpec(
        "FSX-S14", "structural", _C, 1,
        "Header hỏng hoặc mâu thuẫn",
        "Header bị cắt, offset trỏ ra ngoài tệp, số mục vô lý: tệp có thể bị chỉnh tay để làm "
        "hỏng công cụ phân tích.",
        "Tệp tải dở hoặc bị hỏng khi sao chép cũng như vậy.",
        "Kiểm tra lại tệp gốc; nếu cố ý bị làm hỏng thì xử lý như tệp đáng ngờ.",
        ("T1027",),
    ),
    IndicatorSpec(
        "FSX-S15", "structural", _S, 4,
        "Tên lệnh / tên API bị che bằng XOR một byte",
        "Tìm thấy tên lệnh phá khôi phục hoặc tên API mã hoá đang nằm dưới một phép XOR một "
        "byte. Phần mềm bình thường không có lý do giấu tên lệnh của chính hệ điều hành; "
        "giấu chúng chỉ có nghĩa khi tác giả muốn né công cụ dò chuỗi.",
        "Một số trình chống crack, chống gian lận và phần mềm có bảo vệ bản quyền cũng che "
        "chuỗi của chúng theo cách này.",
        "Đọc phần chuỗi đã giải bên dưới: đó mới là năng lực thật của tệp. Coi mọi kết luận "
        "dựa trên chuỗi lộ thiên của tệp này là thiếu.",
        ("T1027", "T1140"),
    ),
    # ---------------------------------------------------------------- năng lực
    IndicatorSpec(
        "FSX-C01", "capability", _C, 1,
        "Duyệt cây thư mục / ổ đĩa",
        "Ransomware phải liệt kê tệp để mã hoá hàng loạt.",
        "Gần như mọi chương trình làm việc với tệp đều duyệt thư mục.",
        "Chỉ có ý nghĩa khi đi cùng năng lực mã hoá và ghi đè ( FSX-C04 ).",
        ("T1083",),
    ),
    IndicatorSpec(
        "FSX-C02", "capability", _C, 1,
        "Dùng mã hoá đối xứng ( AES, ChaCha20, ... )",
        "Ransomware mã hoá nội dung tệp bằng thuật toán đối xứng vì nhanh.",
        "Trình duyệt, VPN, phần mềm sao lưu, trình quản lý mật khẩu đều dùng mã hoá đối xứng.",
        "Chỉ có ý nghĩa khi đi cùng duyệt tệp và ghi đè ( FSX-C04 ).",
        ("T1486",),
    ),
    IndicatorSpec(
        "FSX-C03", "capability", _C, 2,
        "Nạp khoá công khai / mã hoá bất đối xứng",
        "Ransomware hiện đại mã hoá khoá tệp bằng khoá công khai của kẻ tấn công ( mã hoá lai ), "
        "để nạn nhân không tự giải được.",
        "TLS, kiểm tra giấy phép và cập nhật có ký số cũng nạp khoá công khai.",
        "Kết hợp với FSX-T08 ( khoá nhúng ) và FSX-C04 để đánh giá.",
        ("T1486",),
    ),
    IndicatorSpec(
        "FSX-C04", "capability", _S, 4,
        "Đủ chuỗi năng lực mã hoá hàng loạt: duyệt tệp + mã hoá + ghi đè / đổi tên / xoá",
        "Ba năng lực này cùng có mặt là đủ để mã hoá dữ liệu tại chỗ, đúng mô hình của ransomware.",
        "Phần mềm sao lưu có mã hoá, công cụ đồng bộ đám mây và trình nén có mật khẩu cũng hội đủ ba năng lực.",
        "Bật Controlled Folder Access ( Windows ) hoặc giám sát ghi hàng loạt trên máy chủ tệp; "
        "giữ bản sao lưu ngoại tuyến, bất biến.",
        ("T1486", "T1083"),
    ),
    IndicatorSpec(
        "FSX-C05", "capability", _X, 10,
        "Lệnh xoá bản sao bóng / vô hiệu hoá khôi phục hệ thống",
        "vssadmin delete shadows, wmic shadowcopy delete, bcdedit recoveryenabled no, wbadmin "
        "delete catalog... là bước ransomware làm ngay trước khi mã hoá để nạn nhân không tự khôi phục được.",
        "Rất hiếm ở phần mềm lành; đôi khi gặp trong script dọn dẹp của quản trị viên hoặc công cụ sao lưu.",
        "Giám sát và chặn vssadmin / wmic / bcdedit / wbadmin chạy từ tiến trình không phải quản "
        "trị ( quy tắc EDR, ASR 'Use advanced protection against ransomware' ). Giữ sao lưu ngoại tuyến.",
        ("T1490",),
    ),
    IndicatorSpec(
        "FSX-C06", "capability", _S, 4,
        "Danh sách dừng dịch vụ / tiến trình nhắm vào CSDL, sao lưu, bảo mật",
        "Ransomware dừng SQL Server, Exchange, Veeam, phần mềm diệt virus... để mở khoá tệp dữ "
        "liệu trước khi mã hoá và để tắt phòng thủ.",
        "Trình cài đặt / cập nhật cũng dừng dịch vụ, nhưng hiếm khi nhắm cùng lúc nhiều nhóm "
        "( CSDL + sao lưu + bảo mật ).",
        "Bật Tamper Protection cho phần mềm bảo mật; cảnh báo khi một tiến trình dừng hàng loạt dịch vụ.",
        ("T1489", "T1562.001"),
    ),
    IndicatorSpec(
        "FSX-C07", "capability", _C, 2,
        "Dùng Restart Manager để giải phóng tệp đang bị khoá",
        "Restart Manager ( RmGetList / RmShutdown ) cho biết tiến trình nào giữ một tệp và tắt "
        "nó; nhiều dòng ransomware dùng để mã hoá cả tệp đang mở.",
        "Trình cài đặt Windows dùng Restart Manager rất thường xuyên.",
        "Chỉ là bối cảnh; kết hợp với FSX-C04.",
        ("T1489",),
    ),
    IndicatorSpec(
        "FSX-C08", "capability", _C, 2,
        "Liệt kê thư mục chia sẻ mạng",
        "Ransomware liệt kê share SMB để mã hoá cả dữ liệu trên máy chủ tệp.",
        "Trình quản lý tệp và công cụ quản trị mạng cũng liệt kê share.",
        "Hạn chế quyền ghi trên share; giám sát truy cập SMB hàng loạt từ máy trạm.",
        ("T1135", "T1021.002"),
    ),
    IndicatorSpec(
        "FSX-C09", "capability", _C, 1,
        "Cơ chế duy trì ( Run key, scheduled task, cron, LaunchAgent )",
        "Nhiều ransomware tự đăng ký chạy lại sau khởi động để mã hoá tiếp tệp mới.",
        "Rất nhiều phần mềm hợp pháp tự khởi động cùng hệ thống.",
        "Kiểm tra các vị trí khởi động tự động trên máy bị nghi nhiễm ( Autoruns ).",
        ("T1547.001", "T1053"),
    ),
    IndicatorSpec(
        "FSX-C10", "capability", _S, 3,
        "Tự xoá sau khi chạy",
        "Lệnh kiểu 'cmd /c ping 127.0.0.1 & del' xoá chính tệp để xoá dấu vết.",
        "Trình gỡ cài đặt cũng tự xoá theo cách này.",
        "Thu thập bản sao tệp ngay khi phát hiện; dựa vào log EDR / Prefetch / Amcache để điều tra.",
        ("T1070.004",),
    ),
    IndicatorSpec(
        "FSX-C11", "capability", _S, 4,
        "Xoá nhật ký sự kiện / nhật ký hệ thống tệp",
        "wevtutil cl, Clear-EventLog, fsutil usn deletejournal xoá dấu vết điều tra.",
        "Hiếm ở phần mềm lành, trừ công cụ dọn dẹp hệ thống.",
        "Chuyển log về SIEM theo thời gian thực để việc xoá log cục bộ không làm mất dấu.",
        ("T1070.001",),
    ),
    IndicatorSpec(
        "FSX-C12", "capability", _S, 4,
        "Tắt phần mềm bảo mật hoặc khởi động vào Safe Mode",
        "Set-MpPreference -DisableRealtimeMonitoring, thêm loại trừ Defender, tắt tường lửa, "
        "hoặc ép khởi động Safe Mode để mã hoá khi phần mềm bảo mật không chạy.",
        "Rất hiếm ở phần mềm lành ngoài công cụ quản trị.",
        "Bật Tamper Protection; cảnh báo mọi thay đổi cấu hình Defender và bcdedit safeboot.",
        ("T1562.001", "T1562.009"),
    ),
    IndicatorSpec(
        "FSX-C13", "capability", _C, 2,
        "Đổi hình nền màn hình",
        "Nhiều ransomware đổi hình nền thành thông báo đòi tiền.",
        "Ứng dụng tuỳ biến giao diện cũng đổi hình nền.",
        "Chỉ là bối cảnh. Nếu hình nền trên máy thật đã bị đổi thành thông báo đòi tiền thì "
        "đó là sự cố đang diễn ra: cô lập máy và xử lý theo hướng dẫn ở mức kết luận cao.",
        ("T1491.001",),
    ),
    IndicatorSpec(
        "FSX-C14", "capability", _S, 4,
        "Nhắm vào máy ảo / ESXi",
        "Đường dẫn /vmfs/volumes, lệnh esxcli / vim-cmd và đuôi .vmdk .vmx là dấu hiệu của các "
        "biến thể ransomware Linux mã hoá cả máy chủ ảo hoá.",
        "Công cụ quản trị và sao lưu VMware cũng làm việc với các đường dẫn này.",
        "Tắt SSH và ESXi Shell khi không dùng, cô lập mạng quản trị ESXi, vá theo khuyến cáo của VMware.",
        ("T1486", "T1489"),
    ),
    IndicatorSpec(
        "FSX-C15", "capability", _S, 3,
        "Công cụ xoá an toàn / ghi đè không gian trống",
        "cipher /w, sdelete, shred ghi đè dữ liệu đã xoá để không thể khôi phục bản gốc trước khi mã hoá.",
        "Công cụ bảo mật và tiêu huỷ dữ liệu hợp pháp cũng dùng.",
        "Giữ bản sao lưu ngoại tuyến; dữ liệu đã bị ghi đè không khôi phục được bằng công cụ khắc phục.",
        ("T1485", "T1070.004"),
    ),
    IndicatorSpec(
        "FSX-C16", "capability", _S, 4,
        "Truy cập thẳng ổ đĩa vật lý",
        r"Mở \\.\PhysicalDrive0 cho phép ghi đè MBR / bảng phân vùng, kiểu của ransomware khoá "
        "đĩa ( Petya ) và wiper.",
        "Công cụ tạo USB khởi động, sao lưu ảnh đĩa và phân vùng cũng truy cập ổ đĩa vật lý.",
        "Chặn ghi raw disk bằng EDR; giữ ảnh đĩa sao lưu ngoại tuyến.",
        ("T1561.002",),
    ),
    # ---------------------------------------------------------------- nội dung
    IndicatorSpec(
        "FSX-T01", "content", _X, 10,
        "Văn bản ghi chú đòi tiền chuộc",
        "Tệp chứa đoạn văn bản hội đủ nhiều nhóm cụm từ đặc trưng của ghi chú tống tiền: tệp "
        "đã bị mã hoá, cách giải mã, thanh toán, kênh liên lạc ẩn danh, đe doạ.",
        "Bài viết hướng dẫn bảo mật, công cụ huấn luyện nhận thức và chính các bộ dò như công cụ này cũng chứa cụm từ tương tự.",
        "Cô lập máy nếu tệp đã chạy. Không trả tiền chuộc; kiểm tra công cụ giải mã miễn phí "
        "( dự án No More Ransom ) và báo cơ quan chức năng.",
        ("T1486",),
    ),
    IndicatorSpec(
        "FSX-T02", "content", _S, 4,
        "Tên tệp ghi chú tống tiền",
        "Tên kiểu HOW_TO_DECRYPT.txt, RESTORE_FILES.html là nơi ransomware thả ghi chú vào mỗi thư mục.",
        "Hiếm ở phần mềm lành.",
        "Tìm các tệp có tên này trên máy chủ tệp để khoanh vùng thư mục đã bị mã hoá.",
        ("T1486",),
    ),
    IndicatorSpec(
        "FSX-T03", "content", _S, 4,
        "Địa chỉ dịch vụ ẩn Tor ( .onion )",
        "Ransomware dùng trang .onion để nhận tiền chuộc và đăng dữ liệu bị đánh cắp.",
        "Trình duyệt Tor và phần mềm quyền riêng tư cũng chứa địa chỉ .onion.",
        "Chặn lưu lượng Tor ở biên mạng; đưa địa chỉ vào danh sách IOC.",
        ("T1486", "T1090.003"),
    ),
    IndicatorSpec(
        "FSX-T04", "content", _S, 3,
        "Địa chỉ ví tiền mã hoá",
        "Địa chỉ ví Bitcoin / Monero hợp lệ cứng trong tệp là kênh nhận tiền chuộc.",
        "Ví tiền mã hoá và phần mềm khai thác coin cũng chứa địa chỉ ví.",
        "Đưa địa chỉ vào danh sách IOC; chia sẻ với cơ quan chức năng khi báo cáo.",
        ("T1486",),
    ),
    IndicatorSpec(
        "FSX-T05", "content", _C, 2,
        "Kênh liên lạc ẩn danh ( email ẩn danh, Tox, Session )",
        "Ghi chú tống tiền thường cho email ở nhà cung cấp ẩn danh hoặc ID Tox / Session.",
        "Người dùng bình thường cũng dùng các dịch vụ này.",
        "Đưa vào danh sách IOC.",
        ("T1486",),
    ),
    IndicatorSpec(
        "FSX-T06", "content", _S, 3,
        "Danh sách dài đuôi tệp tài liệu / CSDL / sao lưu",
        "Ransomware mang danh sách đuôi tệp cần mã hoá ( .docx .xlsx .sql .bak .vmdk ... ).",
        "Bộ Office, công cụ tìm kiếm, phần mềm sao lưu và diệt virus cũng có danh sách đuôi tệp.",
        "Kết hợp với FSX-T07 và FSX-C04 để đánh giá.",
        ("T1083", "T1486"),
    ),
    IndicatorSpec(
        "FSX-T07", "content", _S, 3,
        "Danh sách loại trừ tệp hệ thống",
        "Ransomware bỏ qua boot.ini, ntldr, ntuser.dat, thư mục Windows... để máy vẫn khởi động "
        "được và nạn nhân đọc được ghi chú.",
        "Phần mềm sao lưu và đồng bộ cũng bỏ qua vài tệp hệ thống, nhưng hiếm khi nhiều như vậy.",
        "Kết hợp với FSX-T06 và FSX-C04 để đánh giá.",
        ("T1083",),
    ),
    IndicatorSpec(
        "FSX-T08", "content", _C, 2,
        "Khoá công khai được nhúng sẵn",
        "Ransomware mã hoá lai nhúng khoá công khai RSA / Curve25519 của kẻ tấn công.",
        "Phần mềm kiểm tra cập nhật, giấy phép và ghim chứng chỉ cũng nhúng khoá công khai.",
        "Ghi lại khoá ( modulus ) làm IOC: cùng khoá ở hai mẫu nghĩa là cùng chiến dịch.",
        ("T1486",),
    ),
    IndicatorSpec(
        "FSX-T09", "content", _C, 1,
        "Hằng số của thuật toán mã hoá ( AES S-box, ChaCha / Salsa )",
        "Thuật toán mã hoá tự cài đặt để lại bảng hằng đặc trưng dù không import API nào.",
        "Mọi thư viện mã hoá liên kết tĩnh ( OpenSSL, mbedTLS, Go crypto ) đều có các hằng này.",
        "Chỉ là bối cảnh. Chỉ đáng xem khi tệp KHÔNG import API mã hoá nào của hệ điều hành mà "
        "vẫn có các hằng này, vì đó là dấu hiệu thuật toán được tự cài đặt để tránh bị theo dõi.",
        ("T1486",),
    ),
)

SPECS: Dict[str, IndicatorSpec] = {spec.id: spec for spec in _SPECS}


def spec(indicator_id: str) -> IndicatorSpec:
    return SPECS[indicator_id]
