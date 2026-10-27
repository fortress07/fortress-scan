# Nhật ký thay đổi

Mọi thay đổi đáng kể của Fortress Scan được ghi ở đây.

Số bản theo [Semantic Versioning](https://semver.org/lang/vi/). Từ 0.1.0, mã rule ( `FSB-*` ), khoá
trong JSON/SARIF và cờ dòng lệnh là **giao diện ổn định**: chỉ đổi ở một bản minor mới, kèm ghi chú
ở đây.

---

## Chưa phát hành

**73 rule trên 35 họ lỗ hổng, 22 ngôn ngữ, 2524 kiểm tra tự động.**

### Thêm

- **Luồng dữ liệu xuyên tệp cho JavaScript/TypeScript, Java và Go** ( #18 ). Chỉ mục dự án, tóm tắt
  hàm, suy kiểu qua factory và constructor, luồng đi qua template, mapper SQL và cấu hình. Python
  theo thêm được lớp, kế thừa và re-export. Đo bằng corpus ba tầng trong `tests/corpus` và
  `python tools/benchmark.py`.
- **21 rule trên 12 họ ngoài injection** ( #19 ): mật mã yếu, tắt xác minh TLS, secret viết cứng, JWT
  không kiểm chữ ký, CORS mở kèm credentials, cookie phiên thiếu HttpOnly, quyền quyết định bằng dữ
  liệu người gửi, mass assignment, quyền tệp quá rộng, tệp tạm đoán trước được, chế độ gỡ lỗi bật,
  prototype pollution.
- **Chín ngôn ngữ mới** ( #20 ): C, C++, Objective-C kèm sáu luật an toàn bộ nhớ `FSB-MEM`, Kotlin,
  Scala, Groovy ( cả Jenkinsfile ), Swift, Dart, Elixir. Java, C# và Go được đào sâu thêm: SQL dựng
  trong biến hay `StringBuilder`, tham số handler của Spring và ASP.NET, redirect, SSRF, XSS.
- **Truy vết xâm nhập** ( #22 ): 11 rule `FSB-IR` trả lời "đã có ai vào đây chưa", đọc cả `crontab`,
  unit systemd, `authorized_keys`, `sudoers`, `ld.so.preload`, `.htaccess`. Kết luận dựa trên cả
  tệp, nên một lời gọi `eval` bình thường không bị gọi là webshell.
- **Phân tích tệp thực thi tìm dấu hiệu ransomware, beta** ( #21 ): `fscan binary` đọc PE, .NET,
  ELF, Mach-O, JAR/APK, PyInstaller và script bằng Python thuần; 40 dấu hiệu trên 26 kỹ thuật
  ATT&CK; giải được chuỗi bị che bằng XOR một byte. Trên 1.108 tệp lành không tệp nào bị gắn từ mức
  "đáng ngờ" trở lên. Tệp không bao giờ được chạy, giải nén ra đĩa hay gửi đi đâu.

### Sửa khi gộp #18, #19, #20

- **Một lỗ hổng chỉ báo một lần.** `prepareStatement(sql)` và `new ObjectInputStream(body)` đã là
  sink, nên `st.execute()` hay `in.readObject()` theo sau không báo lại nữa.
- **Đầu ra của lệnh và nội dung tệp không mang vết bẩn của đối số.** `exec.Command(...).Output()` hay
  `os.ReadFile(p)` ghi ra phản hồi không còn bị gọi là XSS; chính lời gọi lệnh, lời gọi đọc tệp vẫn
  được xét như cũ.
- Tham số khai bằng annotation chỉ sống trong thân hàm của nó ( #20 ), và phần tóm tắt hàm cho luồng
  xuyên tệp ( #18 ) giờ cũng tôn trọng phạm vi đó.
- Corpus của #18 sau khi gộp: tầng 2 và tầng 3 bắt đủ 100%, trước đó mỗi tầng còn sót một lỗi.

### Đổi

- Tên dự án là **Fortress Scan**, gói cài đặt là `fortress-scan`. Đường dẫn trong `pyproject.toml` và
  trong SARIF trỏ về đúng kho.
- README viết lại cho gọn. Hình minh hoạ còn năm hình; hình "hai bộ phân tích" ghi đúng phần xuyên
  tệp mới.
- Bỏ những thứ không còn dùng: `docs/RELEASE.md` ( hướng dẫn cho một lần phát hành đã qua ),
  `tests/generate_unicode_sample.py` ( không ai gọi tới ), ba hình đã lỗi thời ( số đo cũ, thống kê
  rule, độ phủ ngôn ngữ ), và phần "tầng 4" của `tools/benchmark.py` ( trỏ tới tệp không có trong
  kho ).

### Còn biết là chưa đúng

- `FSB-IR-002` ( dropper ) báo nhầm trên một controller Spring nhỏ có `ScriptEngineManager` và
  `Class.forName`.
- `FSB-DESER-002` báo trên `yaml.load(fs.readFileSync("config.yml"))` dù tệp cấu hình là của dự án.

---

## 0.1.0, bản chính thức đầu tiên

Khép lại giai đoạn thử nghiệm. **35 rule trên 17 họ injection, 14 ngôn ngữ và định dạng, 1185 kiểm
tra tự động, không phụ thuộc ngoài.**

### Thêm

- **Bốn ngôn ngữ**: Rust, PowerShell, Perl, Lua ( cả OpenResty `ngx.*` ).
- **Workflow GitHub Actions là mã nguồn**, có bộ phân tích riêng và bốn rule `FSB-CI`: biểu thức
  `${{ }}` dán vào `run:`, dán vào `github-script`, pwn request, action ghim bằng nhãn di động.
- **`--diff`** chỉ báo phát hiện chạm vào dòng vừa đổi, **`--explain`** giải thích từng rule,
  **`--fail-on-confidence`** chặn CI theo từng phát hiện đủ chắc.
- **Trường `evidence`** cho mọi phát hiện, có mặt ở console, JSON, SARIF và Markdown.
- **Ngữ cảnh tệp**: phát hiện trong `tests/`, `examples/`, mã sinh hay mã đi mượn bị hạ một nấc độ
  tin cậy, không bao giờ bị giấu.
- **Đối chiếu OWASP Top 10:2025**, giữ nhãn 2021 đi kèm.
- **Hình minh hoạ sinh từ mã** bằng `tools/generate_diagrams.py`, có test so từng byte.

### Sửa

- **Mười chỗ cho kết quả sai nghiêm trọng**: `<<` của phép dịch bit bị đọc nhầm thành heredoc làm
  mất phát hiện ở phần đuôi tệp; chú thích kiểu Python bị tin như đã ép kiểu; hai lỗi giống hệt
  trong một tệp dùng chung vân tay nên baseline che cả lỗi mới; sáu đường tắt cảnh báo bằng chỉ thị
  nằm trong chuỗi; một bài test tự làm mình đỏ vì ngưỡng không theo cỡ đầu vào.
- **Hai lỗ hổng từ chối dịch vụ trên chính bộ dò**: `redact()` chạy bậc hai trên dòng dài ( 3 giây
  cho 32 KB, vá xong còn 0,007 giây ), regex của `package.json` quay lui ( 23 giây cho 200 KB ).
- **`--baseline`** không còn đọc được `/dev/zero` hay FIFO; cả ba cờ nhận đường dẫn đi qua cùng một
  phép kiểm.
- **Bốn lỗ hổng tìm bằng cách tự tấn công**: tệp ignore bị đọc trọn vào RAM, chi phí so khớp ignore
  không có trần ( vá xong thì `.gitignore` bình thường cũng nhanh hơn hẳn ), tên tệp chèn được chuỗi
  thoát vào terminal, mười đường lách tắt cảnh báo bằng chuỗi `%q{}` của Ruby và `<<eot` của Perl.

### Thay đổi phá vỡ tương thích

- `Finding` có thêm `evidence`, `context`, `occurrence`; `summary` trong JSON có thêm `out_of_diff`.
- Vân tay của phát hiện đầu tiên trong mỗi nhóm giữ nguyên nên baseline cũ vẫn dùng được.
- Phát hiện nằm ngoài đường chạy sản phẩm ra ở độ tin cậy thấp hơn một nấc. CI đang chặn theo
  `--min-confidence` thì anh em chạy lại một lượt để xem con số mới trước khi tin.
