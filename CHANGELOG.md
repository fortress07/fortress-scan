# Nhật ký thay đổi

Mọi thay đổi đáng kể của Fortress Scan Basic Injection được ghi ở đây.

Số bản theo [Semantic Versioning](https://semver.org/lang/vi/). Từ 0.1.0 trở đi, bộ mã rule
(`FSB-*`), khoá trong JSON/SARIF và các cờ dòng lệnh được coi là **giao diện ổn định**. Chúng chỉ
đổi theo một bản minor mới, kèm ghi chú ở đây.

---

## Chưa phát hành

### Thêm: phân tích tệp thực thi tìm dấu hiệu ransomware ( beta )

Lệnh con mới `fortress-scan binary <tệp hoặc thư mục>` đọc thẳng byte của một tệp đã biên dịch
và chấm xem nó có mang chân dung ransomware hay không. Vẫn **không phụ thuộc thư viện ngoài**,
vẫn **không nối mạng**, và **không bao giờ chạy tệp được phân tích**: tệp chỉ được mở đúng một
lần ở chế độ đọc, có bài kiểm tra đếm số lần `open()` để chắc điều đó.

- **Đọc 8 họ định dạng** bằng Python thuần: PE ( kể cả metadata .NET ), ELF ( 32 / 64, LE / BE ),
  Mach-O ( kể cả universal ), JAR / WAR / APK / zipapp, Java `.class`, PyInstaller CArchive,
  buildinfo của Go, và script PowerShell / batch / VBScript / JScript / HTA / shell / Python kèm
  bóc base64 nhiều lớp, gzip, `-EncodedCommand` và UTF-16.
- **40 dấu hiệu** ( 15 cấu trúc, 16 năng lực, 9 nội dung ) trên **26 kỹ thuật ATT&CK**, mỗi dấu
  hiệu kèm bằng chứng, vị trí trong tệp, lý do, trường hợp lành có thể gây ra nó, và việc nên làm.
- **Khôi phục chuỗi bị che bằng XOR một byte.** Đo trước khi vá: XOR riêng vùng chuỗi của một tệp
  mang đủ dấu hiệu làm kết luận tụt từ "rõ rệt" ( 100 điểm ) xuống "cần lưu ý" ( 20 ), và XOR kèm
  bảng import rút gọn thì tụt hẳn về "sạch". Cách vá dùng tính bất biến của hiệu XOR giữa hai byte
  liền nhau nên chỉ cần **một lượt quét thay cho 255**; vùng quanh chỗ trúng được giải rồi cho chạy
  lại cả 40 dấu hiệu, và bản thân việc che giấu thành dấu hiệu `FSX-S15`. Sau khi vá, cả hai ca
  trên trở lại "rõ rệt". Mỏ neo là tên lệnh và tên API của hệ điều hành, không phải chuỗi của một
  họ mã độc cụ thể. Phép này **không** bắt được khoá lặp nhiều byte, phép cộng, RC4 hay AES, và
  README nói rõ điều đó.
- **Kết luận theo trụ, không cộng điểm.** Entropy cao và dấu packer không bao giờ tự đẩy kết luận
  quá mức "cần lưu ý", vì một trình cài đặt bị nén có đúng chân dung đó.
- **Chặn trần cho tài liệu phát hiện.** Tệp dày đặc mã ATT&CK, mã CWE và cú pháp regex bị chặn ở
  mức "đáng ngờ" và được nói rõ lý do, nên luật Sigma, luật YARA hay chính `catalogue.py` của công
  cụ không bị gọi là ransomware. Trần chỉ áp cho script và tệp văn bản.
- **Báo cáo console, JSON và Markdown**, có `--fail-on`, `--only-flagged`, `--max-size`,
  `--max-files`, và mã thoát dùng được cho cổng CI. Tên tệp và chuỗi trong tệp đều được trung hoà
  trước khi in, nên một tệp đặt tên bằng chuỗi thoát terminal không viết đè được lên báo cáo.
- **Đo trên 1.108 tệp lành** ( 626 MB ): 0 tệp đạt mức "đáng ngờ" trở lên, 14 tệp "cần lưu ý",
  1.094 tệp "sạch". Đo lại bằng `tools/measure_binary_corpus.py`. Trên 11 mẫu dựng từng byte
  trong test, 11 / 11 đạt từ mức "nhiều khả năng" trở lên.
- **229 bài kiểm tra riêng** cho phần này, gồm đột biến từng byte có seed cố định, cắt cụt tệp ở
  mọi độ dài, header nói dối, zip bomb, Zip Slip, và một bài quét AST chắc rằng cả gói không gọi
  `eval`, `exec`, `marshal`, `pickle`, `subprocess` hay `socket`.

Đây là bản **beta**: không dịch ngược lệnh máy, không bung tệp đã pack, không kiểm tính hợp lệ
của chữ ký số, và không có cơ sở dữ liệu họ mã độc. README nói rõ từng giới hạn một.

### Truy vết xâm nhập: 11 rule trả lời "đã có người vào đây chưa"

Mọi rule trước đây trả lời "mã này có thể bị khai thác". Họ `FSB-IR` trả lời một câu khác:
"đã có người khai thác xong và để lại cái gì". Khác biệt đó đổi cả quy trình xử lý của người
đọc, nên nó được tách thành ba họ riêng ( `webshell`, `persistence`, `access-backdoor` ) chứ
không gộp vào một nhãn chung với injection.

| Nhóm | Rule | Bắt được |
| :--- | :--- | :--- |
| Webshell và cửa hậu | `FSB-IR-001` `-002` `-003` | tệp nhỏ trong thư mục tải lên nhận lệnh từ request rồi giải mã và thực thi; dropper; cổng mật khẩu cứng trước sink |
| Cơ chế trụ lại | `FSB-IR-010` `-011` `-012` `-013` | `cron.d` tải script về chạy; `ExecStart` trỏ vào `/tmp`; khối base64 giải ra rồi chạy; `ld.so.preload` |
| Cửa hậu truy cập | `FSB-IR-014` `-015` `-016` | khoá SSH mang `command=`; tài khoản thứ hai UID 0; `NOPASSWD: ALL` |
| Thực thi trong thư mục tải lên | `FSB-IR-017` | `.htaccess` bật `AddHandler` ngay trong `uploads/` |

### Đọc được những tệp mà không ai coi là mã nguồn

Thêm lớp tệp `ir-artifact`: `crontab`, unit `systemd` ( `.service` `.timer` `.socket` ), tệp rc
của shell, `authorized_keys`, `ld.so.preload`, `sudoers`, `passwd`, `.htaccess`, cấu hình
`nginx`/`apache`, cùng nội dung của `cron.d`, `profile.d`, `sudoers.d`, `init.d`,
`sites-enabled`. Không tệp nào trong số đó có phần mở rộng mà bảng ngôn ngữ nhận ra, nên **bộ
duyệt cây trước đây không hề liệt kê chúng** - mà đó đúng là nơi cơ chế trụ lại được cắm vào.

Phép nhận theo vị trí luôn nhường cho phép nhận theo tên: `scripts/init.d/x.py` vẫn là Python.
Thiếu phép nhường đó thì một thư mục trùng tên sẽ âm thầm gỡ cả cây con khỏi phần dò injection.

### Kết luận trên cả tệp, không trên một dòng

Bộ dò webshell tính điểm theo năm trụ trên toàn tệp ( đầu vào từ xa, nơi thực thi, lớp làm rối,
dấu che, cổng mật khẩu ) thay vì khớp mẫu theo dòng. Khi chỉ có *đầu vào tới sink* mà không trụ
nào nói về việc cắm ghép, họ `FSB-IR` **im lặng** và nhường cho các rule injection: gọi một lỗi
lập trình là "webshell" sẽ đẩy một ca ứng cứu đi truy vụ xâm nhập không có thật.

Mã đi mượn và mã sinh tự động không bao giờ bị kết luận là bị cắm. Ở đó phép hạ một nấc của
`calibration` là chưa đủ, vì câu "có người cắm tệp này vào" sai hẳn về bản chất chứ không chỉ
kém chắc.

### Một lỗ hổng phát hiện trên chính bộ dò, tìm bằng cách tự quét

Bản đầu của bộ dò webshell **báo nhầm vào mã của chính nó**: `indicators.py` liệt kê `eval(` và
`$_POST` dưới dạng chuỗi, mà phép so chuỗi con không phân biệt được *gọi* với *nhắc tới*.
`test_samples_corpus.py` bắt được ngay lần chạy đầu. Cùng lớp báo nhầm đó sẽ xảy ra trên mọi bộ
quy tắc WAF, mọi luật YARA và mọi tài liệu viết về webshell.

Phép vá là một bộ xóa nội dung chuỗi và chú thích **giữ nguyên độ dài**. Giữ độ dài là điều kiện
bắt buộc chứ không phải tiện lợi: vị trí dòng và cột báo cho người đọc được tính bằng offset trên
văn bản này, nên một phép cắt sẽ làm mọi phát hiện trỏ lệch sang chỗ khác. Bảng dấu hiệu vì vậy
tách làm hai nhóm: dấu hiệu là *lời gọi* thì dò trên mã đã xóa chuỗi, dấu hiệu bản chất là *tham
số dạng chuỗi* ( `php://input`, `display_errors` ) thì dò trên văn bản thô. Trụ sink bắt buộc
phải là mã thật, và đó là phép kiểm giữ cho cả mô hình đứng được.

Bản đầu của bộ xóa duyệt từng ký tự và tốn 117 micro giây mỗi KB, tức là một kho 100 MB phải trả
thêm mười mấy giây. Bản sau nhảy giữa các vị trí đáng quan tâm bằng `str.find` và nhớ vị trí kế
tiếp của từng token, nên mỗi token quét toàn tệp đúng một lượt: **38,8 micro giây mỗi KB, nhanh
hơn 3,0 lần**, và chi phí tuyến tính theo độ dài tệp thay vì theo số chuỗi nhân số token. Tính
tuyến tính đó có bài đo riêng trên 10 hình dạng đầu vào thù địch cho 3 ngôn ngữ, cùng cách
`test_regex_complexity.py` canh các mẫu regex.

### Số liệu

**46 rule trên 20 họ lỗ hổng. 1588 kiểm tra tự động**, trong đó 87 bài cho riêng phần truy vết
xâm nhập: mỗi rule một hiện vật thật, một cây thư mục lành phải im lặng hoàn toàn, phép nhận loại
hiện vật cho 19 đường dẫn, và bộ đo tính tuyến tính của bộ xóa.

---

## 0.1.0, bản chính thức đầu tiên

Bản này khép lại giai đoạn thử nghiệm. Trước nó, công cụ đã đi qua nhiều vòng dựng và tự kiểm
toán; toàn bộ lịch sử đó nằm trong git, còn đây là mốc đầu tiên được phát hành như một sản phẩm.

**35 rule trên 17 họ injection, đối chiếu OWASP Top 10:2025. 14 ngôn ngữ và định dạng.
1185 kiểm tra tự động. Không phụ thuộc thư viện ngoài.**

### Phân tích sâu hơn, kêu oan ít hơn

Mỗi mục dưới đây có một cặp kiểm tra "phải im lặng / phải bắn" trong `tests/test_precision_guards.py`.
Vế thứ hai đứng đó để chặn đúng một đường: cách sửa dễ nhất cho mọi báo nhầm luôn là tắt bớt rule,
và bộ test vẫn xanh trong khi công cụ mù thêm một chút.

- **Ngữ cảnh tệp** (`core/context.py`). Phát hiện trong `tests/`, `examples/`, mã do máy sinh hay
  mã đi mượn bị hạ **đúng một nấc** độ tin cậy, được gắn nhãn `context:*`, và **không bao giờ bị
  giấu đi**. Tắt bằng `--no-context-demotion`. Phép phân loại khớp theo từng thành phần đường dẫn
  và theo ranh giới từ, nên `latest.py`, `contest/` hay `sample_rate.py` vẫn là mã sản phẩm.
- **`assert x in CHO_PHEP`** được đọc như `if x not in CHO_PHEP: raise`.
- **Lớp `enum.Enum` do chính dự án khai báo** là một danh sách cho phép. `Lenh(gia_tri)` hoặc khớp
  một thành viên, hoặc ném `ValueError`; không có nhánh thứ ba.
- **`bang.get(khoa)`** không còn mang vết nhiễm của *khoá* sang giá trị trả về. Phép tra bằng ngoặc
  vuông vốn đã tính đúng, và đây là cùng một sự việc viết bằng lời gọi phương thức.
- **Tham số đã được framework ép kiểu** không còn bị coi là chuỗi tự do: bộ chuyển kiểu trong route
  (`@app.route('/x/<int:so>')`) và chú thích kiểu ở các framework thật sự thi hành nó.
- **`sqlalchemy.text('... :id')`** kèm tham số ràng buộc không còn bị gọi là "câu lệnh không phải hằng".
- **Phép ép kiểu tiền tố** (`[int]$args[0]` của PowerShell) được nhận là bộ khử độc.
- Ở các ngôn ngữ quét theo token, **trường của một giá trị bẩn giờ cũng bẩn**:
  `const q = req.query; exec(q.host)`. Trước đây chỉ tên đầy đủ mới được tra, nên cách viết phổ
  biến nhất của mọi framework rơi thẳng qua lưới.

### Bằng chứng đi kèm mọi phát hiện

Mỗi phát hiện mang theo trường `evidence` nói rõ nguồn nào, đường đi mấy bước, có qua ranh giới tệp
không, ngữ cảnh tệp có hạ mức không. Trường này có mặt ở **cả bốn định dạng**: console (`-v`),
JSON, SARIF (trong `properties`) và Markdown. Ngưỡng `--min-confidence` được áp lại **sau** khi
hiệu chỉnh, nên con số người dùng đặt là con số họ nhận được.

### Phạm vi quét rộng hơn

- **Bốn ngôn ngữ mới**: Rust, PowerShell, Perl, Lua (kể cả OpenResty `ngx.*`).
- **Workflow GitHub Actions là mã nguồn**, và có bộ phân tích riêng (`analysis/workflow.py`) với
  bốn rule mới:
  - `FSB-CI-001`, biểu thức `${{ ... }}` không tin cậy dán thẳng vào khối `run:`;
  - `FSB-CI-002`, dán vào script inline của `actions/github-script`;
  - `FSB-CI-003`, "pwn request": workflow đặc quyền checkout mã của pull request;
  - `FSB-CI-004`, action bên thứ ba ghim bằng nhãn di chuyển được thay vì digest.

  Nhận cả `.gitea/workflows` và `.forgejo/workflows`, vì chúng chạy lại đúng bộ chạy đó.

### Ba tính năng cho việc dùng hằng ngày

- **`--diff patch`** chỉ báo phát hiện chạm vào dòng vừa đổi. Đây là thứ khiến một bộ dò tĩnh sống
  được trong CI, vì pull request không còn đỏ vì nợ của người khác. Tệp **không đổi vẫn được phân
  tích**, do sink cũ của nó có thể vừa được một tệp mới đổi gọi tới. Công cụ **không tự chạy
  `git`**; nó đọc patch anh em đưa vào, nên vẫn không sinh tiến trình con nào.
- **`--explain FSB-SQL-001`** in đầy đủ vì sao rule đó là lỗ hổng và cách sửa đúng.
- **`--fail-on-confidence`** chặn CI theo từng phát hiện đủ chắc chắn, chứ không theo mức cao nhất
  của từng chiều gộp lại thành một phát hiện không có thật.

### Mười chỗ từng cho kết quả sai nghiêm trọng

Sai ở đây không phải báo thừa một dòng. Sai ở đây là bỏ sót một lỗ hổng thật, hoặc che mất một lỗ
hổng vừa được thêm vào, trong khi vẫn in ra chữ "sạch". Tất cả đều tìm được bằng cách tự tấn công
công cụ, và đều có kiểm tra hồi quy trong `tests/test_wrong_results.py` cùng
`tests/test_suppression_multiline.py`.

**Hai chỗ bỏ sót.**

- `<<` không phải lúc nào cũng mở heredoc; nó còn là toán tử dịch trái. Bộ tách token nhận
  `my $mask = 1 << 8;` là mở heredoc, và vì không có dòng kết thúc nào nên toàn bộ phần đuôi tệp
  rơi vào một chuỗi. Mọi phát hiện trong đó biến mất, không lỗi, không cảnh báo. Shell dính cùng
  lỗi với `V=$(( 1 << 8 ))`. Vá bằng hai luật lấy thẳng từ cú pháp của chính các ngôn ngữ đó: nhãn
  heredoc là một định danh nên không mở đầu bằng chữ số, và nhãn trần của Perl phải dính liền `<<`.
- Chú thích kiểu của Python không được ép lúc chạy, và Flask cũng không ép. Bản đầu coi
  `def h(so: int)` là bằng chứng đã ép kiểu, nên `@app.route('/x/<so>')` kèm chú thích đó im lặng
  nuốt một command injection còn nguyên. Giờ chỉ tin chú thích khi tệp có nhập một framework thật
  sự ép kiểu (fastapi, litestar, blacksheep, ninja).

**Một chỗ che mất lỗi mới.** Vân tay cố ý không chứa số dòng, để thêm một dòng import không biến
mọi phát hiện phía dưới thành phát hiện mới. Nhưng thế thì hai dòng thủng giống hệt nhau trong cùng
một tệp cho ra cùng một vân tay, và một mục baseline che cả hai: người ta thêm một lỗ hổng thứ hai
mà cổng CI vẫn xanh. Đã thêm số thứ tự trong nhóm trùng nhau. Phát hiện đầu tiên giữ nguyên vân tay
cũ nên mọi baseline đã ghi vẫn dùng được.

**Sáu đường tắt cảnh báo.** Cùng một họ lỗ hổng đã vá cho heredoc của PHP, Ruby và shell: một dòng
trông như dữ liệu với người review, nhưng bộ mặt nạ đọc nó như mã, nên dấu `#` hay `--` ở đầu dòng
mở ra một "chú thích" và cả tệp tắt tiếng. Bản này thêm bốn ngôn ngữ cùng một bộ phân tích workflow
mà chưa mở rộng bộ mặt nạ theo, nên mở lại sáu cửa: chuỗi ngoặc `[[ ]]` của Lua, here-string
`@" "@` của PowerShell, heredoc của Perl, chuỗi nhiều dòng của Rust, scalar đặt trong nháy của
YAML, và block scalar `|` của YAML. Vá bằng cách khai đúng cú pháp cho từng ngôn ngữ, cộng hai cơ
chế mới: chuỗi có dấu đóng cố định, và khối đóng bằng thụt lề.

**Một bài kiểm tra tự làm mình đỏ.** `test_regex_complexity` đổi cỡ đầu vào từ 16 lần lên 128 lần
mà ngưỡng tỉ lệ vẫn để ở 60, tức là nằm dưới mức tuyến tính. Giờ ngưỡng suy ra từ chính cỡ đầu vào
nên không lệch được nữa.

### Hai lỗ hổng từ chối dịch vụ trên chính bộ dò

Mô hình đe doạ rất cụ thể: kẻ tấn công không chạy được mã trên máy nạn nhân, nhưng đặt được nội
dung vào một repo và nhờ nạn nhân quét nó. Cả hai lỗi dưới đây kích hoạt bằng một tệp dưới 2 MB, và
cả hai đều được **đo bằng đồng hồ** trước và sau khi vá.

- **`redact()` chạy bậc hai trên một dòng dài.** Mẫu bắt mật khẩu trong URL viết
  `[a-z][a-z0-9+.\-]*://`. Lớp ký tự đó nuốt được cả chữ, số và dấu chấm, còn `:` thì không nằm
  trong nó, nên trên một dòng không có `://` bộ máy quét tới cuối rồi lùi từng ký tự để dò dấu hai
  chấm, và làm lại như vậy ở **mọi** vị trí bắt đầu. Đo được **3,0 giây cho 32 KB**; tăng 16 lần
  kích thước thì tốn gấp **276 lần** thời gian. `redact()` chạy trên từng dòng sinh ra trích đoạn
  của mọi phát hiện, nên một tệp JavaScript đã minify nằm trên một dòng là đủ để treo lượt quét
  hàng giờ. Đã ghim độ dài tên giao thức ở 30 ký tự và thêm trần 8 KB cho một lần gọi. Sau khi vá
  còn **0,007 giây**, và phẳng.
- **Ba mẫu dò script vòng đời trong `package.json` quay lui 400 × 200 tổ hợp.** Đo được **23 giây
  cho 200 KB**. Đã thay bằng một lượt quét: tìm từ khoá bằng alternation của chuỗi cố định, rồi soi
  cửa sổ phía sau bằng `str.find`. Kết quả nhận dạng không đổi, có test khoá lại cả bản bắt đúng
  lẫn bản không bắt bừa; thời gian trên đường đi thật giảm từ **0,45 giây xuống 0,02 giây**. Thêm
  chặn trên **200 lệnh vòng đời** mỗi tệp, vì một khoá vòng đời nhận được cả danh sách nên
  `{"postinstall": ["…4000 ký tự…", ×500]}` gói gọn trong 2 MB mà bắt bộ dò làm việc gấp 500 lần.

Kèm theo là hai bài kiểm tra mới. `tests/test_regex_complexity.py` **đo** chứ không đọc mọi regex
trong `src/` trên 18 hình dạng đầu vào thù địch, và bắt lỗi khi thời gian tăng phi tuyến; nó tự áp
dụng cho mọi regex viết thêm sau này. `tests/test_denial_of_service.py` giữ lại đúng những hình
dạng đã làm sập thật.

Ngoài ra, một loạt regex được viết lại cho không còn chỗ quay lui ngay cả trên giấy: thay `\s` bằng
`[ \t]` ở chỗ hai lớp ký tự chồng lấn nhau, thay `.{0,80}?` bằng `[^)]{0,80}`, bỏ các nhánh
alternation không bao giờ được chọn, và gỡ hằng `SHELL_METACHARACTERS` chết.

### Một chỗ đọc tệp thiếu phép kiểm

Ba cờ nhận đường dẫn đọc vào là `--config`, `--baseline` và `--diff`. Mỗi cờ tự kiểm theo một kiểu,
và một trong ba cái kiểm thiếu: `--baseline` không hỏi "đây có phải tệp thường không", nên
`--baseline /dev/zero` đi lọt. `stat()` báo kích thước 0 nên qua được hạn mức, rồi `read_text()`
đọc mãi không hết. Một FIFO còn tệ hơn, vì lượt quét đứng im vô hạn, không lỗi, không dấu vết, đúng
kiểu hỏng tệ nhất cho một cổng CI.

Cả ba giờ đi qua `security.paths.validate_input_path()`: phân giải đường dẫn **trước** khi chạm vào
hệ thống tệp, nên `..` và liên kết được quy về đích thật rồi mới đem đi kiểm; bắt buộc là tệp
thường; và áp hạn mức kích thước. Liên kết do chính người dùng gõ vẫn được đi theo, khác hẳn tệp
cấu hình mà công cụ tự tìm thấy trong cây bị quét, cái đó do người viết repo đặt nên vẫn bị từ chối.

Đây cũng là chỗ SonarCloud chỉ ra bằng `pythonsecurity:S8707`.

### Tự siết lại chính mình

Hai bộ đọc mới đều coi đầu vào là **không tin cậy**:

- patch có trần kích thước (8 MB), trần tổng số dòng thay đổi (200 000), và đường dẫn trong đó bị
  chặn không cho thoát ra ngoài cây quét (`..`, đường dẫn tuyệt đối, tên bị git trích dẫn);
- phép tra khoảng dòng dùng `bisect` thay vì quét tuyến tính, để một patch lớn không làm chính công
  cụ chậm theo cấp số nhân;
- mẫu `${{ ... }}` chỉ chạy trên dòng có chứa nó và bị cắt ở 16 KB, nên một tệp rải đầy `${{` không
  bao giờ đóng không biến công cụ thành nạn nhân của tệp nó đang đọc;
- bộ đọc workflow có trần số dòng, số biểu thức và số dòng mỗi khối.

### Bốn lỗ hổng nữa trên chính bộ dò, tìm bằng cách tự tấn công

Cùng mô hình đe doạ với phần trên: kẻ tấn công đặt được nội dung vào một repo rồi nhờ nạn nhân
quét nó. Ba trong bốn chỗ dưới đây nằm đúng ở phần công cụ tự nhận là đã siết, và cả bốn đều có
kiểm tra hồi quy trong `tests/test_scanner_hardening_0_1_0.py`.

**Hai chỗ từ chối dịch vụ, cùng một gốc: tệp ignore là đầu vào không tin cậy duy nhất chưa có
trần.** Mọi đường đọc khác đều đã đo trước khi đọc ( cấu hình 256 KB, baseline 16 MB, patch 8 MB,
mã nguồn 2 MB ), riêng `.gitignore` và `.fortress-scanignore` thì không.

- **Đọc trọn tệp vào RAM trước khi bất kỳ hạn mức nào kịp đếm.** Hạn mức cũ đếm theo *số mẫu*, mà
  phép đếm đó chỉ chạy được sau khi `read_text()` đã nuốt xong cả tệp. Một `.gitignore` **210 MB
  gồm toàn dòng chú thích**, tức là không sinh ra lấy một quy tắc nào và không đổi kết quả quét
  một chút nào, đẩy đỉnh bộ nhớ lên **637 MB**; nhân theo kích thước thì một tệp vài GB là đủ để
  runner CI bị hạ. Trần 1 MB giờ đứng **trước** phép đọc, và vượt trần thì bỏ hẳn cả tệp quy tắc
  chứ không giấu gì. Sau khi vá, cùng tệp đó tốn **7,2 MB**.
- **Chi phí so khớp không có trần cộng dồn.** `_MAX_TOTAL_TOKENS` chặn được độ phức tạp của *một*
  lần so, nhưng khâu duyệt cây gọi phép so một lần cho *mỗi* entry, nên chi phí thật là
  `tokens × độ dài đường dẫn × số entry`, và hai thừa số sau không có trần nào. Một `.gitignore`
  **15 KB hợp lệ về mọi mặt** ( 30 dòng, dưới mọi hạn mức cũ ) trên 200 tệp nằm sâu 20 cấp kéo
  lượt quét từ **0,7 giây lên 96 giây**; nhân theo trần 50 000 tệp mặc định thì thành hàng giờ.

  Vá bằng hai lớp. Lớp một là một phép **lọc trước chính xác**: mọi mẫu đều bắt buộc chứa đoạn ký
  tự nguyên văn dài nhất của nó, và phép thử đó chạy ở tốc độ C nên loại gần hết số quy tắc trước
  khi phải dựng bảng quy hoạch động. Lớp hai là **hạn mức chung cho cả lượt quét**; cạn thì bỏ hết
  quy tắc thay vì so tiếp, và báo cáo nói ra dưới mã `ignore-budget-exhausted`, đúng hướng an toàn
  đã dùng cho `overflowed`.

  Phép lọc trước là tối ưu chứ không phải một luật khớp mới, và có một bài kiểm tra đối chiếu
  **3 000 cặp mẫu/đường dẫn ngẫu nhiên** với chính bảng quy hoạch động để khoá điều đó lại.

  Đây không chỉ là chuyện an ninh: một `.gitignore` **thật** cũng nhanh lên theo. Quét chính kho
  này đo được **175 ô mỗi tệp**, và bộ mẫu Python + Node của GitHub giảm từ **2,26 ms xuống
  0,037 ms** cho mỗi entry, tức là một kho 50 000 tệp đi từ khoảng **113 giây xuống 1,8 giây**.

**Một chỗ tiêm chuỗi thoát vào terminal qua tên tệp.** Công cụ dựng hẳn một lớp trung hoà cho mọi
đường ra, nhưng CPython in tên tệp **thẳng** ra stderr khi mã được quét sinh ra một
`SyntaxWarning` ( chỉ cần `x = "\d"` ), và đường đó không đi qua lớp ấy. Tên tệp thì do người viết
cây thư mục đặt. Hệ quả là một tệp đặt tên kèm `[2K` xoá được dòng terminal của người chạy,
còn `U+202E` ( RIGHT-TO-LEFT OVERRIDE, **hợp lệ trong tên tệp trên cả Windows lẫn Linux** ) đảo
ngược đoạn tên hiển thị. Đúng thứ mà họ rule `FSB-UNI-*` của chính công cụ này tồn tại để bắt.
Tên tệp đưa cho `ast.parse()` giờ đi qua `neutralize()` trước.

**Mười đường lách tắt cảnh báo còn sót, trên hai ngôn ngữ.** Cùng họ với những lần trước, và lần
này là hai dạng chuỗi chưa từng được mô tả:

- **Chuỗi phần trăm của Ruby và Perl** ( `%q{}`, `%Q()`, `%w[]`, `%i{}`, `q()` ) là dạng chuỗi duy
  nhất mà *người viết tự chọn lấy dấu đóng*, nên không tra được trong bảng cố định. Không mô tả
  thì ruột của chúng bị đọc như mã, và `n = %q{# fortress-scan: ignore-file}` tắt sạch cả tệp dù
  dòng đó không có lấy một chú thích nào. Bộ mặt nạ giờ đọc dấu mở ra từ chính dòng đó, và đếm
  được độ sâu cho bốn cặp ngoặc lồng nhau.
- **Nhãn heredoc trần bị bắt phải viết hoa** ở Ruby và Perl. Lý do cũ là để `arr << item` không bị
  nuốt, nhưng thứ tách heredoc khỏi toán tử dịch trái là **khoảng trắng**, không phải kiểu chữ:
  `<<eot` viết thường là heredoc hợp lệ ( đã chạy thử trên **perl 5.42**, cả `<<eot`, `<<eoT` lẫn
  `<<~eot` đều in ra chỉ thị dưới dạng dữ liệu ). Nhãn trần giờ nhận mọi kiểu chữ và phải dính
  liền `<<`, đúng cách hai ngôn ngữ đó phân biệt.

### Đối chiếu OWASP Top 10:2025

Bộ rule trước đây gộp cả 35 rule vào đúng **hai** mục của bản 2021, mà gộp thô như vậy là ánh xạ
sai chứ không phải ánh xạ gọn. Giờ mỗi rule được xếp theo **OWASP Top 10:2025**, và trải trên
**năm** mục: A05 Injection ( 20 rule ), A08 Software or Data Integrity Failures ( 7 ), A03
Software Supply Chain Failures ( 4 ), A01 Broken Access Control ( 3 ), A02 Security
Misconfiguration ( 1 ).

Ba chỗ bản 2025 xếp khác hẳn bản 2021: **SSRF** thôi đứng riêng và về chung với Broken Access
Control; **chuỗi cung ứng** tách thành mục riêng thay vì nấp trong A08; **path traversal** và
**open redirect** về đúng nhà A01.

Nhãn 2021 **vẫn được giữ nguyên đi kèm** trong cùng trường `owasp`, vì mã rule và khoá JSON của
bản 0.1.0 là giao diện ổn định nên chỉ được thêm vào chứ không được thay bằng thứ người dùng cũ
không tra ra. Cả hai đều có mặt trong JSON và trong `tags` của SARIF.

### Hình minh hoạ được SINH ra, không vẽ tay

README có bảy hình mô tả lại mô hình: đường đi của dữ liệu, sáu bước của một lượt quét, bộ rule
theo mức độ và theo họ, đối chiếu OWASP, độ phủ ngôn ngữ, hai bộ phân tích đặt cạnh nhau, và bốn
phép đo trước/sau khi vá. Mỗi hình có hai bản sáng và tối, nhúng bằng thẻ `<picture>` nên tự đổi
theo chế độ màu của người đọc.

Chúng do `tools/generate_diagrams.py` sinh ra chứ không vẽ tay, vì hình vẽ tay có một kiểu hỏng
rất êm: thêm một rule là con số trên hình sai, mà hình vẫn hiện ra bình thường nên không ai nhận
ra. Mọi con số trên hình đọc thẳng từ `core.registry`, còn `tests/test_diagrams.py` chạy lại bộ
sinh rồi so từng byte với tệp đã commit. Sửa mã mà quên chạy lại là CI đỏ.

Số đo hiệu năng không suy ra được từ mã nên nằm trong một bảng riêng của bộ sinh, kèm cả trung vị,
khoảng min/max và số lần lặp ( 7 lần mỗi phép ).

### Thay đổi phá vỡ tương thích

- `Finding` có thêm ba trường `evidence`, `context` và `occurrence`; hai trường đầu xuất hiện trong
  JSON và SARIF. Mã đọc báo cáo theo khoá cố định không bị ảnh hưởng; mã kiểm tra "tập khoá phải
  khớp đúng" thì có.
- `summary` trong JSON có thêm `out_of_diff`.
- **Vân tay của phát hiện đầu tiên trong mỗi nhóm không đổi**, nên baseline cũ vẫn dùng được. Chỉ
  những phát hiện trùng lặp thứ hai trở đi mới nhận vân tay mới, và đó chính là chỗ trước đây bị
  che nhầm.
- Phát hiện nằm ngoài đường chạy sản phẩm giờ ra ở độ tin cậy thấp hơn một nấc. Nếu CI của anh em
  đang chặn theo `--min-confidence`, hãy chạy lại một lượt để xem con số mới trước khi tin.
