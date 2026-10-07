from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Tuple

from .model import Category, Confidence, Severity


@dataclass(frozen=True)
class RuleSpec:
    id: str
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    cwe: Tuple[str, ...]
    owasp: Tuple[str, ...]
    description: str
    remediation: str
    references: Tuple[str, ...] = ()


# OWASP Top 10:2025 là mốc chính, nhãn 2021 đi kèm phía sau.
#
# Giữ cả hai vì hai lý do thực tế. Nhiều nơi ( báo cáo tuân thủ, bảng điều
# khiển code scanning, mẫu phiếu kiểm thử ) vẫn đang tính theo 2021, và mã rule
# cùng khoá JSON của bản 0.1.0 là giao diện ổn định nên chỉ được THÊM vào chứ
# không được thay bằng thứ người dùng cũ không tra ra.
#
# Bản 2025 gộp lại vài chỗ đáng chú ý với đúng những gì công cụ này quét:
# SSRF thôi đứng riêng và về chung với Broken Access Control; chuỗi cung ứng
# tách thành một mục riêng ( A03 ) thay vì nấp trong A08; còn XXE vẫn nằm
# trong Security Misconfiguration như từ 2021.
_OWASP_INJECTION = ("A05:2025-Injection", "A03:2021-Injection")
_OWASP_INTEGRITY = (
    "A08:2025-Software or Data Integrity Failures",
    "A08:2021-Software and Data Integrity Failures",
)
# Chuỗi cung ứng phần mềm được nâng thành một mục riêng trong bản 2025.
_OWASP_SUPPLY_CHAIN = (
    "A03:2025-Software Supply Chain Failures",
    "A08:2021-Software and Data Integrity Failures",
)
# Đi ra ngoài phạm vi tài nguyên được phép: path traversal và open redirect.
_OWASP_ACCESS = ("A01:2025-Broken Access Control", "A01:2021-Broken Access Control")
# SSRF không còn là mục riêng của bản 2025; nó về chung với kiểm soát truy cập.
_OWASP_SSRF = (
    "A01:2025-Broken Access Control",
    "A10:2021-Server-Side Request Forgery",
)
# XXE nằm trong Security Misconfiguration, giống cách bản 2021 xếp nó.
_OWASP_MISCONFIGURATION = (
    "A02:2025-Security Misconfiguration",
    "A05:2021-Security Misconfiguration",
)

_RULE_LIST: Tuple[RuleSpec, ...] = (
    RuleSpec(
        id="FSB-EXEC-001",
        title="Dữ liệu không tin cậy chạy tới nơi thực thi mã động",
        category=Category.CODE_EXECUTION,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-94", "CWE-95"),
        owasp=_OWASP_INJECTION,
        description=(
            "Một giá trị có nguồn gốc từ bên ngoài, kẻ tấn công điều khiển được, chảy vào lệnh "
            "biên dịch hoặc thực thi mã lúc chạy. Ai chi phối được giá trị đó sẽ chạy được mã tùy "
            "ý ngay bên trong tiến trình ứng dụng."
        ),
        remediation=(
            "Đừng đem dữ liệu ra thực thi như mã. Thay bằng bảng ánh xạ (dict) các hành động cho "
            "phép, hoặc viết bộ phân tích cho đúng cú pháp bạn cần. Nếu chỉ cần một con số thì ép "
            "kiểu bằng int()/float(); nếu cần đọc một literal thì dùng ast.literal_eval() trên dữ "
            "liệu đã kiểm tra trước."
        ),
        references=("https://cwe.mitre.org/data/definitions/95.html",),
    ),
    RuleSpec(
        id="FSB-EXEC-002",
        title="Thực thi mã động từ biểu thức không phải hằng",
        category=Category.CODE_EXECUTION,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-94",),
        owasp=_OWASP_INJECTION,
        description=(
            "Mã được biên dịch hoặc thực thi từ một giá trị mà bộ phân tích không chứng minh được "
            "là hằng số. Chưa thấy đường đi từ nguồn không tin cậy nào, nên đây là điểm yếu thiết "
            "kế cần rà lại, chưa phải lỗ hổng đã xác nhận."
        ),
        remediation=(
            "Ưu tiên cách làm tĩnh. Nếu buộc phải thực thi động, hãy bảo đảm giá trị đầu vào chỉ "
            "được tạo từ dữ liệu do chính chương trình kiểm soát."
        ),
    ),
    RuleSpec(
        id="FSB-CMD-001",
        title="Dữ liệu không tin cậy chạy vào câu lệnh được shell diễn giải",
        category=Category.COMMAND,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-78",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được nối vào chuỗi lệnh rồi đưa cho shell hệ điều "
            "hành. Các ký tự đặc biệt của shell như ; | & $() ` và xuống dòng cho phép kẻ tấn công "
            "gắn thêm lệnh tùy ý, chạy với đúng quyền của ứng dụng."
        ),
        remediation=(
            "Truyền chương trình và từng tham số thành các phần tử riêng trong danh sách, và tắt "
            "shell (ví dụ subprocess.run([\"git\", \"clone\", url]) với shell=False). Nếu thật sự "
            "cần shell, hãy bọc mọi giá trị chèn vào bằng shlex.quote() và kiểm tra nó theo danh "
            "sách trắng trước."
        ),
        references=("https://cwe.mitre.org/data/definitions/78.html",),
    ),
    RuleSpec(
        id="FSB-CMD-002",
        title="Dữ liệu không tin cậy quyết định chương trình hoặc tham số được chạy",
        category=Category.COMMAND,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-78", "CWE-88"),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được đi tới chỗ tạo tiến trình mà không qua shell. Kẻ "
            "tấn công không nối thêm được lệnh, nhưng vẫn chọn được binary nào sẽ chạy hoặc chèn "
            "thêm cờ tùy chọn vào danh sách tham số, và điều này thường leo thang thành chạy mã."
        ),
        remediation=(
            "Lấy đường dẫn chương trình từ danh sách trắng cố định, đừng lấy từ đầu vào. Chèn dấu "
            "phân cách \"--\" trước các giá trị do người dùng cung cấp để chúng không bị hiểu là "
            "cờ tùy chọn, và kiểm tra định dạng từng tham số."
        ),
    ),
    RuleSpec(
        id="FSB-CMD-003",
        title="Câu lệnh shell được ghép từ biểu thức không phải hằng",
        category=Category.COMMAND,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-78",),
        owasp=_OWASP_INJECTION,
        description=(
            "Chuỗi lệnh đưa cho shell được ghép lúc chạy từ những giá trị không chứng minh được là "
            "hằng. Chưa thấy nguồn không tin cậy nào chạm tới, nhưng đây đúng là kiểu ghép chuỗi "
            "sinh ra lỗi command injection."
        ),
        remediation=(
            "Tắt shell và truyền danh sách tham số. Nếu bắt buộc dùng shell, hãy ghép lệnh chỉ từ "
            "hằng số và bọc mọi phần biến đổi bằng shlex.quote()."
        ),
    ),
    RuleSpec(
        id="FSB-CMD-004",
        title="Biến shell được khai triển mà không đặt trong nháy kép",
        category=Category.COMMAND,
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        cwe=("CWE-78",),
        owasp=_OWASP_INJECTION,
        description=(
            "Script shell khai triển một biến mà không bọc nháy kép. Giá trị sẽ bị tách từ theo "
            "khoảng trắng và bị khai triển ký tự đại diện, nên đầu vào chứa khoảng trắng hay ký tự "
            "đặc biệt sẽ làm thay đổi cấu trúc câu lệnh đang chạy."
        ),
        remediation=(
            "Bọc mọi khai triển trong nháy kép (\"$var\", \"${arr[@]}\"). Ưu tiên mảng thay cho "
            "chuỗi ngăn cách bằng khoảng trắng, và dùng printf %q khi giá trị phải đi qua một "
            "shell lồng bên trong."
        ),
    ),
    RuleSpec(
        id="FSB-SQL-001",
        title="Dữ liệu không tin cậy được nối thẳng vào câu lệnh SQL",
        category=Category.SQL,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-89",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được trở thành một phần của chính câu SQL gửi xuống cơ "
            "sở dữ liệu, thay vì được truyền vào như tham số. Kẻ tấn công đổi được ý nghĩa câu "
            "truy vấn, đọc hoặc sửa dữ liệu tùy ý, và trên nhiều hệ quản trị còn với được tới hệ "
            "điều hành."
        ),
        remediation=(
            "Dùng tham số ràng buộc và giữ nguyên phần chữ của câu lệnh: "
            "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,)). Tên bảng và tên "
            "cột không ràng buộc được, nên phải ánh xạ qua danh sách trắng cố định trong mã."
        ),
        references=("https://cwe.mitre.org/data/definitions/89.html",),
    ),
    RuleSpec(
        id="FSB-SQL-002",
        title="Câu lệnh SQL được ghép bằng định dạng chuỗi",
        category=Category.SQL,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-89",),
        owasp=_OWASP_INJECTION,
        description=(
            "Câu SQL được dựng bằng nối chuỗi, %-format, str.format hoặc f-string. Chưa chứng minh "
            "được nguồn không tin cậy nào chạm tới, nhưng phần chữ của câu lệnh không còn là hằng "
            "và chỉ cách một lần sửa nữa là thành lỗ hổng."
        ),
        remediation=(
            "Đưa mọi phần biến đổi của câu lệnh vào tham số ràng buộc, để bản thân câu SQL luôn là "
            "một chuỗi hằng."
        ),
    ),
    RuleSpec(
        id="FSB-NOSQL-001",
        title="Dữ liệu không tin cậy chạy vào toán tử truy vấn NoSQL",
        category=Category.NOSQL,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-943",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được đi vào truy vấn document store ở vị trí chấp nhận "
            "toán tử hoặc JavaScript chạy phía máy chủ. Chỉ cần gửi một object thay vì giá trị đơn "
            "là kẻ tấn công thay được phép so sánh bằng $ne, $gt hay $where và vượt qua bộ lọc."
        ),
        remediation=(
            "Ép mọi giá trị truy vấn về đúng kiểu vô hướng bạn mong đợi trước khi dựng bộ lọc, từ "
            "chối các khóa bắt đầu bằng \"$\", và tuyệt đối không bật JavaScript phía máy chủ như "
            "$where hay db.eval."
        ),
    ),
    RuleSpec(
        id="FSB-LDAP-001",
        title="Dữ liệu không tin cậy chạy vào bộ lọc LDAP",
        category=Category.LDAP,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-90",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được nhúng vào bộ lọc tìm kiếm LDAP hoặc tên phân biệt "
            "(DN). Các ký tự như * ( ) \\ và NUL làm đổi cấu trúc bộ lọc, có thể dùng để liệt kê "
            "toàn bộ thư mục hoặc vượt qua xác thực."
        ),
        remediation=(
            "Escape mọi giá trị chèn vào bằng hàm escape bộ lọc theo RFC 4515 mà thư viện LDAP của "
            "bạn cung cấp, và kiểm tra riêng từng thành phần của DN."
        ),
    ),
    RuleSpec(
        id="FSB-XPATH-001",
        title="Dữ liệu không tin cậy chạy vào biểu thức XPath",
        category=Category.XPATH,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-643",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được nối vào biểu thức XPath, cho phép viết lại điều "
            "kiện lọc và đọc những nút nằm ngoài phạm vi dự định."
        ),
        remediation=(
            "Dùng cơ chế ràng buộc biến của engine XPath (ví dụ biến XPath trong lxml) thay cho "
            "nối chuỗi."
        ),
    ),
    RuleSpec(
        id="FSB-TMPL-001",
        title="Dữ liệu không tin cậy được biên dịch thành template",
        category=Category.TEMPLATE,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-1336", "CWE-94"),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được trở thành mã nguồn của template chứ không phải dữ "
            "liệu truyền vào template. Các engine template phía máy chủ cho phép duyệt ngược đối "
            "tượng, nên lỗi này gần như luôn leo thang thành chạy mã từ xa."
        ),
        remediation=(
            "Giữ nguồn template cố định và truyền dữ liệu người dùng qua context khi render "
            "(render_template(\"page.html\", name=name) thay vì render_template_string(dl_nguoi_dung)). "
            "Nếu bắt buộc cho người dùng gửi template, hãy render trong môi trường sandbox với "
            "danh sách trắng thuộc tính."
        ),
        references=("https://cwe.mitre.org/data/definitions/1336.html",),
    ),
    RuleSpec(
        id="FSB-TMPL-002",
        title="Template được biên dịch từ biểu thức không phải hằng",
        category=Category.TEMPLATE,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-1336",),
        owasp=_OWASP_INJECTION,
        description=(
            "Một template được biên dịch từ giá trị không phải hằng. Chưa thấy nguồn không tin cậy "
            "nào chạm tới, nhưng đây là điểm sẽ thành lỗi template injection ngay khi giá trị đó "
            "chịu ảnh hưởng từ người dùng."
        ),
        remediation=(
            "Nạp template từ loader và thư mục cố định, thay vì biên dịch chuỗi dựng lúc chạy."
        ),
    ),
    RuleSpec(
        id="FSB-DESER-001",
        title="Dữ liệu không tin cậy chạy vào bộ giải tuần tự nguy hiểm",
        category=Category.DESERIALIZATION,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-502",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Chuỗi byte kẻ tấn công điều khiển được đưa vào bộ giải tuần tự có khả năng dựng lại "
            "đồ thị đối tượng tùy ý. Các định dạng này gọi hàm khởi tạo trong lúc giải mã, nên một "
            "payload được chế tác sẽ chạy mã trước khi ứng dụng kịp kiểm tra kết quả."
        ),
        remediation=(
            "Dùng định dạng chỉ chứa dữ liệu như JSON, hoặc định dạng nhị phân có kiểm tra schema. "
            "Nếu buộc phải dùng pickle, chỉ áp dụng cho dữ liệu cục bộ tin cậy và ký HMAC cho "
            "payload rồi xác minh trước khi giải mã."
        ),
        references=("https://cwe.mitre.org/data/definitions/502.html",),
    ),
    RuleSpec(
        id="FSB-DESER-002",
        title="Đang dùng bộ giải tuần tự nguy hiểm",
        category=Category.DESERIALIZATION,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-502",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Có lời gọi tới bộ giải tuần tự có thể khởi tạo kiểu dữ liệu tùy ý. Chưa truy được đầu "
            "vào về một nguồn không tin cậy, nhưng bất kỳ thay đổi nào sau này khiến byte từ bên "
            "ngoài chạm tới đây đều biến nó thành lỗ hổng chạy mã từ xa."
        ),
        remediation=(
            "Chuyển sang biến thể an toàn mà thư viện cung cấp: yaml.safe_load, json.loads, "
            "torch.load(..., weights_only=True), numpy.load(..., allow_pickle=False)."
        ),
    ),
    RuleSpec(
        id="FSB-IMPORT-001",
        title="Dữ liệu không tin cậy quyết định module hoặc mã được nạp",
        category=Category.DYNAMIC_IMPORT,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-829", "CWE-98"),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được chọn module, tệp hay đường dẫn sẽ được nạp và "
            "thực thi. Nạp một module là chạy mã ở mức cao nhất của module đó, nên điều khiển được "
            "cái tên là điều khiển được việc thực thi."
        ),
        remediation=(
            "Ánh xạ tên được yêu cầu qua một từ điển cố định các module cho phép và từ chối mọi "
            "thứ khác. Tuyệt đối không ghép chuỗi để tạo đường dẫn nạp."
        ),
    ),
    RuleSpec(
        id="FSB-IMPORT-002",
        title="Module được nạp từ biểu thức không phải hằng",
        category=Category.DYNAMIC_IMPORT,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        cwe=("CWE-829",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Một module hoặc tệp mã được nạp từ giá trị không phải hằng. Các hệ thống plugin làm "
            "vậy một cách chính đáng; hãy xác nhận tập ứng viên không thể bị tác động từ bên ngoài."
        ),
        remediation=(
            "Giới hạn bộ nạp trong một thư mục cố định do ứng dụng sở hữu và kiểm tra đường dẫn "
            "sau khi phân giải vẫn nằm trong thư mục đó."
        ),
    ),
    RuleSpec(
        id="FSB-REFL-001",
        title="Dữ liệu không tin cậy quyết định thuộc tính hoặc phương thức được gọi",
        category=Category.REFLECTION,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-470",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được chọn thuộc tính hoặc phương thức nào sẽ được tra "
            "cứu rồi gọi. Đồ thị đối tượng truy cập được qua các thuộc tính dunder cho phép kẻ tấn "
            "công đi từ một lần tra cứu tùy ý tới việc thực thi tùy ý."
        ),
        remediation=(
            "Điều phối qua một bảng ánh xạ tường minh từ tên được phép sang hàm xử lý. Nếu bắt "
            "buộc dùng reflection, hãy từ chối tên chứa \"_\" và kiểm tra đối tượng thu được đúng "
            "là callable thuộc lớp mong đợi."
        ),
    ),
    RuleSpec(
        id="FSB-EL-001",
        title="Dữ liệu không tin cậy chạy vào bộ đánh giá expression language",
        category=Category.EXPRESSION_LANGUAGE,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-917",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được đưa cho engine expression language như SpEL, "
            "OGNL, MVEL hoặc một scripting engine. Các ngôn ngữ này với được tới class loader và "
            "do đó tới cả runtime, dẫn thẳng tới chạy mã từ xa."
        ),
        remediation=(
            "Tuyệt đối không phân tích đầu vào người dùng như một biểu thức. Nếu buộc phải dùng "
            "engine, hãy cấu hình context đánh giá hạn chế, cấm tham chiếu kiểu và cấm gọi phương "
            "thức."
        ),
    ),
    RuleSpec(
        id="FSB-XSS-001",
        title="Dữ liệu không tin cậy chạy vào nơi xuất HTML thô",
        category=Category.MARKUP,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-79",),
        owasp=_OWASP_INJECTION,
        description=(
            "Dữ liệu kẻ tấn công điều khiển được ghi vào nơi trình duyệt hiểu là HTML chứ không "
            "phải văn bản, cho phép chèn script chạy trong chính origin của ứng dụng."
        ),
        remediation=(
            "Gán qua textContent, để engine template tự escape, hoặc làm sạch bằng một thư viện "
            "sanitizer HTML uy tín cấu hình theo danh sách trắng trước khi gán vào innerHTML."
        ),
    ),
    RuleSpec(
        id="FSB-XML-001",
        title="XML được phân tích với chế độ phân giải thực thể ngoài",
        category=Category.XML,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-611",),
        owasp=_OWASP_MISCONFIGURATION,
        description=(
            "Bộ phân tích XML được cấu hình cho phép phân giải thực thể ngoài hoặc nạp DTD. Một "
            "tài liệu được chế tác có thể đọc tệp cục bộ, gọi tới dịch vụ nội bộ trong mạng, hoặc "
            "làm cạn bộ nhớ."
        ),
        remediation=(
            "Tắt nạp DTD và phân giải thực thể trên parser, hoặc dùng thư viện đã gia cố như "
            "defusedxml."
        ),
    ),
    RuleSpec(
        id="FSB-UNI-001",
        title="Ký tự điều khiển hai chiều được nhúng trong mã nguồn",
        category=Category.UNICODE,
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        cwe=("CWE-94", "CWE-1007"),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Tệp chứa ký tự điều khiển hai chiều (bidi override/isolate) của Unicode. Chúng đảo "
            "thứ tự hiển thị của văn bản mà không đổi cách trình biên dịch đọc, nên logic mà người "
            "review nhìn thấy khác với logic thực sự chạy. Đây chính là kỹ thuật Trojan Source để "
            "tuồn mã độc qua vòng review."
        ),
        remediation=(
            "Gỡ bỏ các ký tự này. Nếu thật sự cần văn bản hai chiều, hãy đưa vào tệp tài nguyên "
            "thay vì mã nguồn, và thêm một bước kiểm tra trong CI để chặn các code point này."
        ),
        references=("https://trojansource.codes/",),
    ),
    RuleSpec(
        id="FSB-UNI-002",
        title="Ký tự vô hình hoặc rộng bằng không trong mã nguồn",
        category=Category.UNICODE,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe=("CWE-94",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Tệp chứa các code point vô hình hoặc rộng bằng không. Chúng nấp được bên trong tên "
            "định danh và chuỗi ký tự, khiến hai token trông giống hệt nhau nhưng lại là hai thứ "
            "khác nhau với trình biên dịch."
        ),
        remediation=(
            "Xóa các ký tự này và giới hạn tên định danh trong tập ký tự nhìn thấy được ở khâu lint."
        ),
    ),
    RuleSpec(
        id="FSB-UNI-003",
        title="Token trộn lẫn các bảng chữ cái dễ nhầm",
        category=Category.UNICODE,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        cwe=("CWE-1007",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Một token trộn chữ cái từ nhiều bảng trong nhóm Latin, Cyrillic, Greek và Armenian. "
            "Các bảng này có những chữ trông giống hệt nhau: thay chữ a Latin bằng code point "
            "U+0430 của Cyrillic sẽ tạo ra một cái tên nhìn không phân biệt được với bản gốc nhưng "
            "lại là ký hiệu khác với trình biên dịch, đủ để một tên giả mạo che tên thật. Các hệ "
            "chữ không có glyph trùng với Latin, như tiếng Nhật hay tiếng Trung, không bị báo."
        ),
        remediation=(
            "Giữ mỗi token trong một bảng chữ cái duy nhất. Kiểm tra xem cái tên này có đang cố ý "
            "khác với một tên trông tương tự ở nơi khác trong dự án hay không."
        ),
    ),
    RuleSpec(
        id="FSB-UNI-004",
        title="Ký tự điều khiển khiến các công cụ chia dòng khác nhau",
        category=Category.UNICODE,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe=("CWE-436", "CWE-94"),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Tệp chứa ký tự điều khiển C0/C1 hoặc dấu tách dòng Unicode. Mỗi công cụ hiểu "
            "chúng một kiểu: str.splitlines() của Python, nhiều trình soạn thảo và giao diện "
            "review coi \\v, \\f, \\x1c-\\x1e, NEL, U+2028, U+2029 là xuống dòng, còn trình "
            "biên dịch thì không. Hệ quả là số dòng mà người review nhìn thấy lệch khỏi số "
            "dòng thực sự chạy, nên một dòng vô hại có thể bị trưng ra thay cho dòng nguy "
            "hiểm. Ký tự ESC còn mang được chuỗi điều khiển terminal để viết đè nội dung in "
            "ra console."
        ),
        remediation=(
            "Gỡ bỏ các ký tự này khỏi mã nguồn. Nếu cần chúng trong dữ liệu, hãy viết dạng "
            "escape (\"\\\\x0c\") thay vì nhúng byte thô, và thêm một bước kiểm tra trong CI "
            "để chặn ký tự điều khiển lọt vào tệp mã nguồn."
        ),
        references=("https://cwe.mitre.org/data/definitions/436.html",),
    ),
    RuleSpec(
        id="FSB-SUP-001",
        title="Script vòng đời của package tải mã từ xa về chạy",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-506", "CWE-829"),
        owasp=_OWASP_SUPPLY_CHAIN,
        description=(
            "Một script chạy lúc cài đặt hoặc build tải nội dung về rồi đẩy thẳng vào trình thông "
            "dịch. Ai kiểm soát được endpoint đó, hoặc chặn được kết nối, sẽ chạy mã trên mọi máy "
            "lập trình viên và mọi máy CI cài package này."
        ),
        remediation=(
            "Đưa phụ thuộc vào trong kho (vendor), ghim theo digest, và xác minh chữ ký trước khi "
            "chạy. Loại bỏ hoàn toàn kiểu tải-về-chạy-ngay trong script vòng đời."
        ),
    ),
    RuleSpec(
        id="FSB-SUP-002",
        title="Script vòng đời của package chạy lệnh shell",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        cwe=("CWE-829",),
        owasp=_OWASP_SUPPLY_CHAIN,
        description=(
            "Một script chạy lúc cài đặt có gọi lệnh shell. Chuyện này phổ biến và thường hợp lệ, "
            "nhưng đây đúng là cơ chế mà các payload dependency confusion lợi dụng, nên câu lệnh "
            "này đáng để liếc qua."
        ),
        remediation=(
            "Giữ script cài đặt tối giản, và dùng --ignore-scripts trên CI ở những nơi quá trình "
            "build không cần tới chúng."
        ),
    ),
    RuleSpec(
        id="FSB-PATH-001",
        title="Dữ liệu không tin cậy quyết định đường dẫn tệp được mở",
        category=Category.PATH,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe=("CWE-22", "CWE-73"),
        owasp=_OWASP_ACCESS,
        description=(
            "Một đường dẫn có nguồn gốc từ bên ngoài, kẻ tấn công điều khiển được, đi thẳng vào "
            "việc mở hoặc gửi tệp. Ký tự ../ ( hoặc ..\\ trên Windows ) trong giá trị đó đọc được "
            "tệp nằm ngoài thư mục dự định, kể cả tệp cấu hình và bí mật."
        ),
        remediation=(
            "Rút gọn về tên tệp bằng os.path.basename() hoặc secure_filename rồi mới ghép vào "
            "thư mục gốc, hoặc kiểm tra os.path.realpath() nằm trong thư mục gốc trước khi mở."
        ),
    ),
    RuleSpec(
        id="FSB-SSRF-001",
        title="Dữ liệu không tin cậy quyết định URL ứng dụng tự gửi request tới",
        category=Category.SSRF,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-918",),
        owasp=_OWASP_SSRF,
        description=(
            "Một URL hoặc tên máy có nguồn gốc từ bên ngoài quyết định nơi ứng dụng tự gửi "
            "request. Kẻ tấn công dùng điều đó đọc dịch vụ nội bộ ( metadata cloud, admin panel ) "
            "từ phía máy chủ, quét mạng trong, hoặc biến máy chủ thành proxy hộ họ."
        ),
        remediation=(
            "Cho phép danh sách máy cố định thay vì nhận URL thô; nếu phải nhận URL thì phân tích "
            "bằng urlparse() và kiểm tra hostname trước, và chặn scheme khác http/https."
        ),
    ),
    RuleSpec(
        id="FSB-REDIR-001",
        title="Dữ liệu không tin cậy quyết định nơi chuyển hướng người dùng tới",
        category=Category.REDIRECT,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe=("CWE-601",),
        owasp=_OWASP_ACCESS,
        description=(
            "Một URL chuyển hướng có nguồn gốc từ bên ngoài đi thẳng vào lệnh redirect. Kẻ tấn "
            "công gửi link mang địa chỉ thật của anh em nhưng nhảy sang trang giả mạo, tận dụng "
            "niềm tin của người dùng vào tên miền của anh em."
        ),
        remediation=(
            "Chỉ chấp nhận đường dẫn tương đối, hoặc đối chiếu hostname với một danh sách cho "
            "phép trước khi chuyển hướng. Đừng truyền thẳng URL nhận được."
        ),
    ),
    RuleSpec(
        id="FSB-HDR-001",
        title="Dữ liệu không tin cậy chảy vào header HTTP của phản hồi",
        category=Category.HTTP_HEADER,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe=("CWE-113", "CWE-117"),
        owasp=_OWASP_INJECTION,
        description=(
            "Một giá trị có nguồn gốc từ bên ngoài đi thẳng vào header HTTP của phản hồi. Nếu nó "
            "chứa CR/LF thì chèn được header tùy ý và tách thân phản hồi -- đặt lại Set-Cookie, "
            "Content-Length sai lệch, hay thậm chí thay cả nội dung trang."
        ),
        remediation=(
            "Từ chối giá trị chứa ký tự điều khiển bằng re.fullmatch() với bảng chữ cái cho phép "
            "trước khi đặt vào header, hoặc encode giá trị theo RFC 5987."
        ),
    ),
    RuleSpec(
        id="FSB-CI-001",
        title="Dữ liệu không tin cậy được dán thẳng vào khối run: của workflow CI",
        category=Category.COMMAND,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-78", "CWE-94"),
        owasp=_OWASP_INJECTION,
        description=(
            "Một biểu thức ${{ ... }} lấy giá trị do người ngoài đặt được -- tiêu đề issue, thân "
            "comment, tên nhánh của pull request -- và GitHub thay nó vào script TRƯỚC khi shell "
            "đọc dòng lệnh. Dấu nháy trong workflow không cứu được: kẻ tấn công đóng nháy rồi viết "
            "tiếp lệnh của mình. Lệnh đó chạy trên runner đang giữ GITHUB_TOKEN và mọi secret của "
            "job."
        ),
        remediation=(
            "Đưa giá trị qua biến môi trường rồi mới dùng trong shell: khai báo `env: TIEU_DE: "
            "${{ github.event.issue.title }}` ở bước đó, và trong run: dùng \"$TIEU_DE\". Lúc này "
            "chuỗi đi vào tiến trình qua môi trường chứ không qua văn bản script, nên không còn "
            "ranh giới cú pháp nào để phá."
        ),
        references=(
            "https://securitylab.github.com/resources/github-actions-untrusted-input/",
            "https://docs.github.com/en/actions/security-for-github-actions/security-guides/"
            "security-hardening-for-github-actions",
        ),
    ),
    RuleSpec(
        id="FSB-CI-002",
        title="Dữ liệu không tin cậy được dán vào script inline của một action",
        category=Category.CODE_EXECUTION,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-94",),
        owasp=_OWASP_INJECTION,
        description=(
            "actions/github-script và các action tương tự nhận một đoạn JavaScript rồi eval nó. "
            "Biểu thức ${{ ... }} được thay vào đoạn mã đó trước khi nó chạy, nên dữ liệu do người "
            "ngoài đặt trở thành mã chạy với quyền của token trong job."
        ),
        remediation=(
            "Đọc giá trị qua context của chính action ( `context.payload...` ) hoặc qua "
            "`process.env` sau khi đã gán bằng khối env:, đừng nội suy ${{ ... }} vào thân script."
        ),
        references=("https://github.com/actions/github-script#readme",),
    ),
    RuleSpec(
        id="FSB-CI-003",
        title="Workflow đặc quyền checkout mã của pull request rồi chạy nó",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-829", "CWE-94"),
        owasp=_OWASP_SUPPLY_CHAIN,
        description=(
            "pull_request_target và workflow_run chạy với token ghi được và đọc được secret của "
            "kho, khác hẳn pull_request thường. Checkout đúng mã của pull request trong một "
            "workflow như vậy rồi build hay test nó nghĩa là chạy mã của người lạ ở phía trong "
            "hàng rào -- một script cài đặt hay một bước build là đủ để lấy secret."
        ),
        remediation=(
            "Tách làm hai: workflow pull_request_target chỉ làm việc không cần mã ( gắn nhãn, "
            "bình luận ), còn việc build/test mã đóng góp thì để workflow pull_request thường lo. "
            "Nếu buộc phải checkout thì đừng chạy gì từ cây mã đó và đừng đưa secret vào job."
        ),
        references=(
            "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        ),
    ),
    RuleSpec(
        id="FSB-CI-004",
        title="Action của bên thứ ba được tham chiếu bằng nhãn có thể đổi",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe=("CWE-829", "CWE-494"),
        owasp=_OWASP_SUPPLY_CHAIN,
        description=(
            "`uses: chu-so-huu/action@v3` bám vào một tag hoặc một nhánh, mà cả hai đều do bên kia "
            "di chuyển được bất cứ lúc nào. Ai chiếm được kho đó -- hoặc chính chủ sở hữu đổi ý -- "
            "sẽ chạy mã mới trên runner của bạn mà không cần bạn sửa một dòng nào."
        ),
        remediation=(
            "Ghim theo digest commit đầy đủ: `uses: chu-so-huu/action@<sha 40 ký tự>  # v3.1.0`. "
            "Dependabot vẫn nâng cấp được bản ghim này, còn nội dung thì không đổi sau lưng."
        ),
        references=(
            "https://docs.github.com/en/actions/security-for-github-actions/security-guides/"
            "security-hardening-for-github-actions#using-third-party-actions",
        ),
    ),
    # --- Truy vết xâm nhập ------------------------------------------------
    #
    # Họ FSB-IR trả lời một câu khác mọi rule phía trên. Chúng nói "mã này có
    # thể bị khai thác"; họ này nói "đã có người khai thác xong và để lại cái
    # này". Khác biệt đó không phải chuyện cách gọi tên: một phát hiện FSB-IR
    # không vào hàng đợi sửa lỗi của sprint sau mà vào quy trình ứng cứu ngay
    # hôm nay, vì nếu nó đúng thì hệ thống đang nằm trong tay người khác.
    #
    # Mức độ nghiêm trọng vì vậy được đặt theo "kẻ tấn công ĐANG có gì", chứ
    # không theo "kẻ tấn công có thể làm gì nếu tìm được đường vào".
    RuleSpec(
        id="FSB-IR-001",
        title="Webshell: tệp nhận lệnh từ request rồi thực thi",
        category=Category.WEBSHELL,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-506", "CWE-912"),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Cả tệp này hợp thành một đường điều khiển từ xa: nó đọc dữ liệu request, và dữ liệu "
            "đó tới được nơi thực thi, trong một tệp vừa nhỏ vừa không có khung dự án quanh nó -- "
            "hoặc nằm trong thư mục tải lên, hoặc tự giải mã nội dung trước khi chạy. Đây không "
            "phải một lỗi lập trình mà là một sự việc đã xảy ra: có người ghi được tệp vào cây mã."
        ),
        remediation=(
            "Đừng vá tệp này, hãy coi nó là tang vật. Ghi lại nội dung và thời điểm sửa đổi, tìm "
            "trong log truy cập xem nó được gọi từ đâu và từ khi nào, rồi mới xóa. Sau đó mới là "
            "phần quan trọng hơn: tìm đường mà nó được ghi vào ( lỗ hổng tải tệp, thư mục ghi "
            "được, tài khoản quản trị bị chiếm ) và bịt đường đó, vì tệp bị xóa sẽ quay lại nếu "
            "đường vào còn mở. Cuối cùng chặn thực thi mã trong mọi thư mục tải lên."
        ),
        references=("https://cwe.mitre.org/data/definitions/506.html",),
    ),
    RuleSpec(
        id="FSB-IR-002",
        title="Dropper: nội dung bị làm rối được giải mã rồi chạy ngay",
        category=Category.WEBSHELL,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-506",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Tệp giải mã một khối nội dung rồi thực thi kết quả, mà không đọc đầu vào nào từ bên "
            "ngoài. Đó là hình dạng của tầng chạy trước: lệnh thật không nằm trong tệp, nên không "
            "ai đọc tệp mà biết nó làm gì, và bộ dò theo từ khoá cũng không thấy gì để dò."
        ),
        remediation=(
            "Giải mã khối nội dung đó bằng tay trong môi trường cách ly để biết nó làm gì trước "
            "khi xóa -- chính nó nói ra đường vào và chỗ kẻ tấn công còn đang giữ. Nếu đây là mã "
            "của chính dự án ( bộ nén, bộ đóng gói ) thì giữ nguyên và đánh dấu bằng "
            "`fortress-scan: ignore` kèm lý do, để lần ứng cứu sau không ai phải điều tra lại."
        ),
        references=("https://cwe.mitre.org/data/definitions/506.html",),
    ),
    RuleSpec(
        id="FSB-IR-003",
        title="Cửa hậu có cổng mật khẩu cứng ngay trước nơi thực thi",
        category=Category.WEBSHELL,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-912", "CWE-798"),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Một phép so với hằng băm cứng đứng ngay trước nơi thực thi, trong một tệp nhỏ không "
            "có khung dự án. Cổng đó không bảo vệ ứng dụng mà bảo vệ chính cửa hậu: người cắm nó "
            "không muốn người khác dùng được đường vào của mình."
        ),
        remediation=(
            "Xử lý như FSB-IR-001: ghi lại tang vật, truy đường vào, rồi xóa. Chuỗi băm trong tệp "
            "là một đầu mối dùng được -- tra nó trong các tập mật khẩu đã công bố thường cho ra "
            "ngay bộ công cụ mà kẻ tấn công dùng, và từ đó biết họ còn cắm gì ở nơi khác."
        ),
        references=("https://cwe.mitre.org/data/definitions/912.html",),
    ),
    RuleSpec(
        id="FSB-IR-010",
        title="Cơ chế tự chạy tải mã từ xa về rồi đưa thẳng cho shell",
        category=Category.PERSISTENCE,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-494", "CWE-506"),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Một lịch chạy, một unit của systemd, một tệp rc hoặc một script khởi động tải nội "
            "dung từ xa về và chuyển thẳng cho trình thông dịch. Nội dung chạy không được kiểm "
            "bằng gì cả, và ở đầu bên kia nó đổi được bất cứ lúc nào -- nên quyền trên máy này "
            "thuộc về người giữ địa chỉ đó, không thuộc về người viết dòng này."
        ),
        remediation=(
            "Gỡ dòng này khỏi cơ chế tự chạy và kiểm tra xem nó đã chạy bao nhiêu lần. Nếu đây là "
            "bước cài đặt do chính nhóm viết, hãy tải về trước thành một tệp có băm được ghim, "
            "kiểm băm, rồi mới chạy. Trong một ca ứng cứu thì địa chỉ ở dòng này là đầu mối quan "
            "trọng nhất của toàn bộ hiện trường."
        ),
        references=("https://cwe.mitre.org/data/definitions/494.html",),
    ),
    RuleSpec(
        id="FSB-IR-011",
        title="Cơ chế tự chạy thực thi thứ nằm trong thư mục ai cũng ghi được",
        category=Category.PERSISTENCE,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe=("CWE-426", "CWE-732"),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Đường dẫn được thực thi nằm trong /tmp, /var/tmp, /dev/shm hoặc một thư mục tạm "
            "tương đương. Nội dung ở đó bất cứ tiến trình nào trên máy cũng thay được, nên ai ghi "
            "được một tệp vào đấy sẽ chạy được mã ở lần khởi động kế tiếp, không cần lỗ hổng nào "
            "khác. Một cấu hình do người quản trị viết gần như không bao giờ có hình dạng này."
        ),
        remediation=(
            "Chuyển thứ cần chạy sang thư mục chỉ root ghi được ( /usr/local/bin, /opt ) rồi trỏ "
            "cơ chế tự chạy vào đó. Nếu không nhận ra dòng này là của mình thì coi như dấu vết "
            "xâm nhập: xem tệp đích còn tồn tại không, và nó được tạo lúc nào."
        ),
        references=("https://cwe.mitre.org/data/definitions/426.html",),
    ),
    RuleSpec(
        id="FSB-IR-012",
        title="Cơ chế tự chạy giải mã một khối nội dung rồi thực thi",
        category=Category.PERSISTENCE,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe=("CWE-506",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Lệnh thật được giấu sau một lớp base64 hoặc một lớp nén, rồi kết quả giải mã được "
            "đưa cho shell. Người quản trị đọc tệp cấu hình sẽ không thấy lệnh nào đáng ngờ, và "
            "đó chính là mục đích của lớp mã hóa ở đây -- mã cấu hình hợp pháp không cần che."
        ),
        remediation=(
            "Giải mã khối đó bằng tay để biết nó làm gì, ghi lại, rồi gỡ dòng này. Nếu là bước "
            "cài đặt của chính nhóm thì viết lệnh ra dạng đọc được: một cấu hình mà người trực ca "
            "không đọc nổi là một cấu hình không ai rà soát được."
        ),
        references=("https://cwe.mitre.org/data/definitions/506.html",),
    ),
    RuleSpec(
        id="FSB-IR-013",
        title="Thư viện được nạp trước vào mọi tiến trình",
        category=Category.PERSISTENCE,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-426",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "`ld.so.preload` nạp thư viện được nêu vào mọi tiến trình chạy trên máy, kể cả tiến "
            "trình của root, và thư viện đó ghi đè được cả hàm thư viện chuẩn: `open`, `readdir`, "
            "`execve`. Đây là chỗ rootkit vùng người dùng cắm vào để ẩn tệp và ẩn tiến trình -- "
            "nên từ lúc này, kết quả của mọi công cụ chạy trên máy đó không còn đáng tin. Một hệ "
            "thống bình thường để tệp này rỗng hoặc không có nó. Cùng cơ chế với LD_PRELOAD đặt "
            "trong tệp rc, chỉ khác là phạm vi rộng hơn: toàn máy thay vì một phiên đăng nhập."
        ),
        remediation=(
            "Đừng điều tra tiếp trên chính máy đó. Gắn đĩa của nó vào một hệ thống sạch rồi mới "
            "đọc, vì mọi lệnh chạy trên máy nhiễm đều đi qua thư viện này. Ghi lại tệp .so được "
            "nêu làm tang vật trước khi gỡ, và coi mọi tài khoản từng đăng nhập sau thời điểm tệp "
            "được tạo là đã mất mật khẩu."
        ),
        references=("https://cwe.mitre.org/data/definitions/426.html",),
    ),
    RuleSpec(
        id="FSB-IR-014",
        title="Khóa SSH mang lệnh cưỡng chế hoặc biến môi trường",
        category=Category.ACCESS_BACKDOOR,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe=("CWE-912",),
        owasp=_OWASP_ACCESS,
        description=(
            "Một mục trong `authorized_keys` mang `command=` chạy trình thông dịch, hoặc mang "
            "`environment=`. Dạng thứ nhất cho người giữ khóa riêng một shell ngay khi kết nối, "
            "bất kể tài khoản được cấu hình thế nào; dạng thứ hai đổi được biến môi trường của "
            "phiên, và kèm LD_PRELOAD thì nó đổi luôn mã chạy trong phiên đó."
        ),
        remediation=(
            "Đối chiếu từng khóa trong tệp với danh sách khóa mà nhóm thực sự cấp, theo phần chú "
            "thích ở cuối mỗi dòng và theo dấu vân tay khóa. Gỡ mọi khóa không nhận ra, rồi xem "
            "log đăng nhập xem khóa đó đã được dùng chưa. Khóa triển khai hợp pháp thì giữ "
            "`command=` nhưng trỏ vào đúng một lệnh, kèm `no-pty` và `restrict`."
        ),
        references=("https://cwe.mitre.org/data/definitions/912.html",),
    ),
    RuleSpec(
        id="FSB-IR-015",
        title="Tài khoản thứ hai có UID 0",
        category=Category.ACCESS_BACKDOOR,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-269", "CWE-912"),
        owasp=_OWASP_ACCESS,
        description=(
            "Hệ thống quyết định quyền theo UID chứ không theo tên, nên một tài khoản UID 0 mang "
            "tên khác là root dưới một cái tên khác. Đây là cách một cửa hậu sống qua việc đổi "
            "mật khẩu root và qua việc khóa tài khoản root: người ứng cứu xử lý root rồi tưởng "
            "đã xong."
        ),
        remediation=(
            "Xác nhận với nhóm vận hành rằng tài khoản này không phải của họ, rồi khóa nó và xóa "
            "khỏi `passwd`. Xem thời điểm tạo và các tệp mà nó sở hữu để khoanh vùng thời gian "
            "kẻ tấn công đã ở trong hệ thống. Trên máy thật thì root là tài khoản UID 0 duy nhất; "
            "mọi ngoại lệ phải có lý do viết ra được."
        ),
        references=("https://cwe.mitre.org/data/definitions/269.html",),
    ),
    RuleSpec(
        id="FSB-IR-016",
        title="Quyền sudo mọi lệnh không cần mật khẩu",
        category=Category.ACCESS_BACKDOOR,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-250", "CWE-269"),
        owasp=_OWASP_ACCESS,
        description=(
            "Quy tắc cho chạy mọi lệnh với quyền root mà không cần mật khẩu. Ai đã vào được tài "
            "khoản đó -- qua một webshell, một khóa SSH bị thêm, một mật khẩu bị lộ -- là lên root "
            "ngay, không cần tới lỗ hổng leo thang nào. Độ tin cậy ở mức trung bình vì trong "
            "container và trên máy CI đây đôi khi là cấu hình có chủ ý."
        ),
        remediation=(
            "Thu hẹp còn đúng những lệnh mà vai trò đó cần, viết bằng đường dẫn tuyệt đối, và bỏ "
            "`NOPASSWD` ở những chỗ có người thật ngồi gõ. Nếu quy tắc này không phải của nhóm "
            "thì nó là một cửa hậu leo thang quyền: gỡ ngay và truy xem nó được thêm lúc nào."
        ),
        references=("https://cwe.mitre.org/data/definitions/250.html",),
    ),
    RuleSpec(
        id="FSB-IR-017",
        title="Cấu hình web bật bộ xử lý mã cho thư mục tải lên",
        category=Category.WEBSHELL,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=("CWE-434",),
        owasp=_OWASP_MISCONFIGURATION,
        description=(
            "Một chỉ thị `AddHandler`, `SetHandler`, `AddType` hoặc `Options +ExecCGI` bật bộ xử "
            "lý mã cho thư mục chứa nó. Nếu đó là thư mục tải lên thì mọi tệp người dùng đẩy lên "
            "được đều thành mã chạy trên máy chủ, và việc kiểm tra phần mở rộng lúc tải lên không "
            "còn giá trị gì. Chính kẻ tấn công cũng hay tự ghi tệp `.htaccess` này vào để biến "
            "một chỗ tải tệp vô hại thành đường thực thi mã."
        ),
        remediation=(
            "Nếu tệp cấu hình này không phải của nhóm thì xóa và coi như dấu vết xâm nhập. Nếu là "
            "của nhóm thì tắt hẳn thực thi trong thư mục tải lên: `php_admin_flag engine off` kèm "
            "`SetHandler None`, hoặc tốt hơn là đưa thư mục tải lên ra ngoài gốc tài liệu web và "
            "phục vụ tệp qua một handler của ứng dụng."
        ),
        references=("https://cwe.mitre.org/data/definitions/434.html",),
    ),
)

RULES: Dict[str, RuleSpec] = {rule.id: rule for rule in _RULE_LIST}


def get_rule(rule_id: str) -> RuleSpec:
    try:
        return RULES[rule_id]
    except KeyError:
        raise KeyError("không có rule với mã: %s" % rule_id) from None


def all_rules() -> Iterable[RuleSpec]:
    return tuple(sorted(_RULE_LIST, key=lambda rule: rule.id))


def rules_digest() -> str:
    import hashlib

    digest = hashlib.sha256()
    for rule in all_rules():
        digest.update(rule.id.encode("utf-8"))
        digest.update(b"\x1f")
        digest.update(rule.title.encode("utf-8"))
        digest.update(b"\x1f")
        digest.update(str(int(rule.severity)).encode("utf-8"))
        digest.update(b"\x1e")
    return digest.hexdigest()
