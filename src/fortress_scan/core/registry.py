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
# Thuật toán yếu, khoá viết cứng, IV cố định, PRNG đoán được.
_OWASP_CRYPTO = ("A04:2025-Cryptographic Failures", "A02:2021-Cryptographic Failures")
# Xác minh chứng chỉ ( CWE-295 ) và thông tin đăng nhập viết cứng ( CWE-798 )
# được cả hai bản xếp vào nhóm xác thực, không phải nhóm mật mã.
_OWASP_AUTHENTICATION = (
    "A07:2025-Authentication Failures",
    "A07:2021-Identification and Authentication Failures",
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
        id="FSB-DESER-003",
        title="Bộ giải tuần tự được cấu hình để dữ liệu đầu vào tự chọn kiểu đối tượng",
        category=Category.DESERIALIZATION,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe=("CWE-502",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Một thư viện JSON hay nhị phân vốn chỉ dựng đúng kiểu được khai báo đã bị bật chế độ "
            "đa hình: Json.NET với TypeNameHandling khác None, Jackson với default typing hoặc "
            "LaissezFaireSubTypeValidator, fastjson với autoType, XStream với AnyTypePermission, "
            "Kryo không bắt đăng ký lớp, Oj ở mode :object. Khi đó chính payload quyết định lớp "
            "nào được khởi tạo, và một chuỗi gadget có sẵn trên classpath là đủ để chạy mã. Phân "
            "tích tĩnh không biết dữ liệu đưa vào đây có tới từ bên ngoài hay không, nên mức độ "
            "giữ ở medium; cấu hình thì chắc chắn đã bật."
        ),
        remediation=(
            "Tắt chế độ đa hình ( TypeNameHandling.None, bỏ enableDefaultTyping, tắt autoType ). "
            "Nếu thật sự cần, giới hạn bằng danh sách cho phép: ISerializationBinder của Json.NET, "
            "BasicPolymorphicTypeValidator của Jackson, allowTypes của XStream, register() của Kryo."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
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
    RuleSpec(
        id="FSB-CRYPTO-001",
        title="Hàm băm đã bị phá ( MD5, SHA-1 ) dùng để dựng chữ ký hoặc MAC",
        category=Category.CRYPTO,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-328", "CWE-327"),
        owasp=_OWASP_CRYPTO,
        description=(
            "MD5 và SHA-1 đã có tấn công va chạm thực tế, và kiểu ghép `md5(bi_mat + du_lieu)` "
            "còn bị tấn công nối dài ( length extension ): biết một chữ ký hợp lệ là tự làm ra "
            "chữ ký cho dữ liệu dài hơn mà không cần biết bí mật. Rule chỉ bắn khi dữ liệu được "
            "băm hoặc nơi nhận kết quả mang tên bí mật hay chữ ký; băm nội dung tệp để làm ETag "
            "hay khoá cache thì không bị báo."
        ),
        remediation=(
            "Dùng HMAC với SHA-256 ( hmac.new(key, msg, hashlib.sha256), crypto.createHmac"
            "('sha256', key) ) và so sánh chữ ký bằng hàm so sánh hằng thời gian."
        ),
        references=("https://cwe.mitre.org/data/definitions/328.html",),
    ),
    RuleSpec(
        id="FSB-CRYPTO-002",
        title="Mật khẩu được băm bằng hàm băm nhanh thay vì hàm dẫn xuất khoá chậm",
        category=Category.CRYPTO,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe=("CWE-916", "CWE-759"),
        owasp=_OWASP_CRYPTO,
        description=(
            "MD5, SHA-1 và cả SHA-256 được thiết kế để chạy NHANH: một GPU thử hàng tỉ mật khẩu "
            "mỗi giây. Lộ bảng người dùng là lộ gần hết mật khẩu, kể cả khi có muối. Rule bắn "
            "khi đầu vào của hàm băm mang tên mật khẩu và không nằm bên trong một hàm dẫn xuất "
            "khoá chậm."
        ),
        remediation=(
            "Dùng argon2id, scrypt hoặc bcrypt qua thư viện chuẩn của nền tảng: "
            "argon2-cffi / passlib, password_hash() của PHP, BCryptPasswordEncoder của Spring, "
            "golang.org/x/crypto/bcrypt."
        ),
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
        ),
    ),
    RuleSpec(
        id="FSB-CRYPTO-003",
        title="Thuật toán mã hoá đã bị phá ( DES, 3DES, RC4, RC2, Blowfish )",
        category=Category.CRYPTO,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe=("CWE-327",),
        owasp=_OWASP_CRYPTO,
        description=(
            "DES có khoá 56 bit, vét cạn được trong vài giờ. 3DES và Blowfish có khối 64 bit nên "
            "dính tấn công Sweet32 khi mã hoá nhiều dữ liệu với cùng khoá. RC4 có độ lệch thống "
            "kê đủ để khôi phục bản rõ lặp lại ( cookie, token )."
        ),
        remediation="Dùng AES-GCM hoặc ChaCha20-Poly1305 qua một API mã hoá có xác thực.",
        references=("https://cwe.mitre.org/data/definitions/327.html",),
    ),
    RuleSpec(
        id="FSB-CRYPTO-004",
        title="Mã hoá khối ở chế độ ECB",
        category=Category.CRYPTO,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe=("CWE-327",),
        owasp=_OWASP_CRYPTO,
        description=(
            "ECB mã hoá từng khối độc lập: hai khối bản rõ giống nhau cho ra hai khối bản mã "
            "giống nhau, nên cấu trúc dữ liệu lộ ra nguyên vẹn, và kẻ tấn công cắt ghép khối được "
            "mà không bị phát hiện. Với Java, `Cipher.getInstance(\"AES\")` không ghi chế độ "
            "cũng chính là AES/ECB."
        ),
        remediation=(
            "Dùng chế độ có xác thực: AES/GCM/NoPadding với nonce ngẫu nhiên 12 byte, hoặc "
            "AESGCM / ChaCha20Poly1305 của thư viện cryptography."
        ),
        references=("https://cwe.mitre.org/data/definitions/327.html",),
    ),
    RuleSpec(
        id="FSB-CRYPTO-005",
        title="IV, nonce hoặc muối là hằng số viết cứng",
        category=Category.CRYPTO,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe=("CWE-329", "CWE-1204", "CWE-760"),
        owasp=_OWASP_CRYPTO,
        description=(
            "IV cố định với CBC làm hai bản rõ có cùng phần đầu cho ra cùng phần đầu bản mã. "
            "Nonce cố định với GCM, CTR hay ChaCha20 nghiêm trọng hơn nhiều: cùng khoá và cùng "
            "nonce là cùng dòng khoá, XOR hai bản mã ra XOR hai bản rõ, và với GCM còn khôi phục "
            "được khoá xác thực để giả mạo bản mã. Muối cố định biến mọi mật khẩu thành một bảng "
            "tra chung."
        ),
        remediation=(
            "Sinh IV / nonce / muối mới bằng CSPRNG cho từng lần mã hoá ( os.urandom, "
            "crypto.randomBytes, SecureRandom, crypto/rand ) và lưu kèm bản mã."
        ),
        references=("https://cwe.mitre.org/data/definitions/329.html",),
    ),
    RuleSpec(
        id="FSB-CRYPTO-006",
        title="Khoá mật mã viết cứng trong mã nguồn",
        category=Category.CRYPTO,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe=("CWE-321", "CWE-798"),
        owasp=_OWASP_CRYPTO,
        description=(
            "Một hằng chuỗi được đưa thẳng làm khoá cho bộ mã hoá, HMAC hay chữ ký JWT. Ai đọc "
            "được mã nguồn, bản build hay lịch sử git đều giải mã được dữ liệu và ký được token "
            "hợp lệ; muốn xoay khoá thì phải phát hành lại phần mềm."
        ),
        remediation=(
            "Nạp khoá từ trình quản lý bí mật hoặc biến môi trường lúc chạy, và xoay ngay khoá "
            "đã nằm trong lịch sử git vì xoá commit không thu hồi được nó."
        ),
        references=("https://cwe.mitre.org/data/definitions/321.html",),
    ),
    RuleSpec(
        id="FSB-CRYPTO-007",
        title="Bộ sinh số ngẫu nhiên đoán được dùng cho giá trị bảo mật",
        category=Category.CRYPTO,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-338", "CWE-330"),
        owasp=_OWASP_CRYPTO,
        description=(
            "random của Python, Math.random của JavaScript, java.util.Random, math/rand của Go, "
            "rand()/mt_rand() của PHP đều là PRNG thống kê: quan sát vài đầu ra là dựng lại được "
            "trạng thái và đoán trước mọi token kế tiếp. Dùng chúng cho token đặt lại mật khẩu, "
            "OTP hay session id là cho phép chiếm tài khoản. Rule chỉ bắn khi giá trị đi vào một "
            "tên mang nghĩa bảo mật; độ tin cậy vì thế là medium."
        ),
        remediation=(
            "Dùng CSPRNG: secrets.token_urlsafe(), crypto.randomBytes() / crypto.randomUUID(), "
            "SecureRandom, crypto/rand, random_bytes() / random_int()."
        ),
        references=("https://cwe.mitre.org/data/definitions/338.html",),
    ),
    RuleSpec(
        id="FSB-CRYPTO-008",
        title="Khoá RSA hoặc DSA ngắn hơn 2048 bit",
        category=Category.CRYPTO,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe=("CWE-326",),
        owasp=_OWASP_CRYPTO,
        description=(
            "RSA 512 bit phân tích được trên máy thuê vài giờ; 1024 bit nằm trong tầm của tổ chức "
            "có tài nguyên và đã bị NIST loại từ 2013. Khoá sinh ra hôm nay thường sống nhiều năm."
        ),
        remediation="Dùng RSA tối thiểu 2048 bit ( 3072 nếu khoá sống lâu ), hoặc Ed25519 / P-256.",
        references=("https://cwe.mitre.org/data/definitions/326.html",),
    ),
    RuleSpec(
        id="FSB-TLS-001",
        title="Tắt xác minh chứng chỉ TLS hoặc khoá máy chủ",
        category=Category.TLS,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe=("CWE-295", "CWE-297"),
        owasp=_OWASP_AUTHENTICATION,
        description=(
            "Kết nối vẫn được mã hoá nhưng không còn biết đang nói chuyện với ai: bất kỳ ai đứng "
            "giữa đường ( Wi-Fi công cộng, proxy, DNS bị đầu độc ) đưa ra một chứng chỉ tự ký là "
            "đọc và sửa được toàn bộ lưu lượng, kể cả mật khẩu và token đi trong đó."
        ),
        remediation=(
            "Bỏ cờ tắt xác minh. Với CA nội bộ, trỏ tới đúng tệp CA ( verify='/duong/dan/ca.pem', "
            "ca:, RootCAs ) thay vì tắt hẳn; với SSH, nạp known_hosts và dùng RejectPolicy."
        ),
        references=("https://cwe.mitre.org/data/definitions/295.html",),
    ),
    RuleSpec(
        id="FSB-SECRET-001",
        title="Mật khẩu, token hoặc khoá API viết cứng trong mã nguồn",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-798", "CWE-259"),
        owasp=_OWASP_AUTHENTICATION,
        description=(
            "Một giá trị trông như bí mật thật được gán cho tên mang nghĩa mật khẩu, token hay "
            "khoá, hoặc khớp định dạng token của nhà cung cấp ( AWS, GitHub, Slack, Stripe, khoá "
            "riêng PEM ). Giá trị mẫu, chuỗi rỗng, tên biến môi trường và chuỗi có khoảng trắng "
            "bị loại; độ tin cậy lên high khi định dạng hoặc độ ngẫu nhiên của chuỗi xác nhận nó. "
            "Báo cáo luôn che giá trị."
        ),
        remediation=(
            "Thu hồi và xoay bí mật ngay, vì nó đã nằm trong lịch sử git. Sau đó nạp từ biến môi "
            "trường hoặc trình quản lý bí mật, và thêm bước quét secret vào CI."
        ),
        references=("https://cwe.mitre.org/data/definitions/798.html",),
    ),
    RuleSpec(
        id="FSB-JWT-001",
        title="JWT được chấp nhận mà không xác minh chữ ký",
        category=Category.JWT,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe=("CWE-347", "CWE-345"),
        owasp=_OWASP_AUTHENTICATION,
        description=(
            "Token được giải mã với xác minh chữ ký bị tắt ( verify_signature: False, "
            "JWT.decode(t, k, false), ParseUnverified ), hoặc bộ kiểm tra chấp nhận token không ký "
            "( thuật toán 'none', parseClaimsJwt, RequireSignedTokens = false ). Ai cũng sửa được "
            "phần claims rồi tự ký lại bằng 'none', nên mọi quyết định dựa trên sub, role hay "
            "user_id trong token đều bị qua mặt. Lời gọi chỉ đọc iss hay kid trước khi xác minh "
            "thật trong cùng hàm không bị báo; khi không thấy chỗ xác minh nào khác thì độ tin cậy "
            "chỉ ở medium, vì chữ ký có thể đã được kiểm ở một tầng khác như gateway."
        ),
        remediation=(
            "Luôn xác minh bằng khoá và danh sách thuật toán cố định: jwt.decode(t, key, "
            "algorithms=['RS256']), jwt.Parse với keyfunc kiểm tra token.Method, parseSignedClaims "
            "của jjwt, TokenValidationParameters giữ RequireSignedTokens = true. Không bao giờ để "
            "'none' trong danh sách thuật toán."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/347.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        ),
    ),
    RuleSpec(
        id="FSB-CORS-001",
        title="CORS phản chiếu mọi origin kèm theo thông tin đăng nhập",
        category=Category.CORS,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe=("CWE-942", "CWE-346"),
        owasp=_OWASP_MISCONFIGURATION,
        description=(
            "Phản hồi vừa dội lại Origin của người gửi vào Access-Control-Allow-Origin, vừa đặt "
            "Access-Control-Allow-Credentials: true. Hai thứ đó đi cùng nhau có nghĩa là trang web "
            "nào cũng gọi được API này bằng cookie của nạn nhân VÀ đọc được nội dung trả về, nên dữ "
            "liệu sau đăng nhập ( thông tin cá nhân, token CSRF, kết quả truy vấn ) chảy sang tên "
            "miền của kẻ tấn công. Cấu hình để Access-Control-Allow-Origin là đúng ký tự '*' KHÔNG "
            "bị báo: trình duyệt từ chối '*' khi request có credentials, nên đó không phải lỗ hổng "
            "này. Khai thác cần cookie đi kèm được request khác site, tức là cookie đặt "
            "SameSite=None -- đúng trường hợp của phần lớn API bật CORS kèm credentials -- hoặc "
            "HTTP Basic / client cert."
        ),
        remediation=(
            "Liệt kê thẳng những origin được phép thay vì dội lại Origin hoặc dùng mẫu '*': "
            "CORS(app, origins=['https://app.example'], supports_credentials=True), "
            "cors({ origin: ['https://app.example'], credentials: true }), "
            "allowedOrigins('https://app.example') của Spring, WithOrigins(...) của ASP.NET. Khi "
            "danh sách phải động thì so khớp Origin với một allowlist đóng rồi mới ghi header, và "
            "luôn thêm Vary: Origin để cache không trộn phản hồi của hai origin."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/942.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html",
        ),
    ),
    RuleSpec(
        id="FSB-COOKIE-001",
        title="Cookie phiên hoặc token được đặt mà không có cờ HttpOnly",
        category=Category.COOKIE,
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-1004",),
        owasp=_OWASP_MISCONFIGURATION,
        description=(
            "Cookie mang phiên đăng nhập hoặc token được ghi mà không có HttpOnly, hoặc có nhưng bị "
            "tắt thẳng ( httponly=False, httpOnly: false, setHttpOnly(false) ). Mặc định của "
            "Flask, Django response.set_cookie và express res.cookie đều là KHÔNG có HttpOnly, nên "
            "chỉ cần thiếu tham số là cookie đọc được bằng document.cookie. Đây là lớp phòng thủ "
            "thứ hai: một mình nó không cho ai vào, nhưng khi có XSS thì nó quyết định kẻ tấn công "
            "chỉ hành động trong phiên của nạn nhân hay mang hẳn cookie phiên đi dùng chỗ khác. "
            "Cookie tên csrf hay xsrf không bị báo vì JavaScript của chính trang phải đọc được "
            "chúng để gắn vào request."
        ),
        remediation=(
            "Đặt HttpOnly cho mọi cookie mà JavaScript của trang không cần đọc: "
            "response.set_cookie(name, value, httponly=True, secure=True, samesite='Lax'), "
            "res.cookie(name, value, { httpOnly: true, secure: true, sameSite: 'lax' }), "
            "cookie.setHttpOnly(true). Với Flask và Django, giữ SESSION_COOKIE_HTTPONLY = True; "
            "với PHP, session.cookie_httponly = 1."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/1004.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ),
    ),
    RuleSpec(
        id="FSB-ACCESS-001",
        title="Quyền được quyết định bằng giá trị người gửi tự đặt được",
        category=Category.ACCESS_CONTROL,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe=("CWE-807", "CWE-285"),
        owasp=_OWASP_ACCESS,
        description=(
            "Một trường của request -- tham số truy vấn, trường form, cookie hay header -- mang "
            "tên quyền ( role, is_admin, superuser ) và được đem ra so để quyết định cho phép hay "
            "không. Người gửi tự đặt được cả ba thứ đó bằng một dòng curl, nên ai cũng tự cấp "
            "được quyền quản trị: thêm `?role=admin` hoặc một cookie `is_admin=1` là xong. Quyền "
            "phải tra từ phía máy chủ theo danh tính đã xác thực ( phiên đã ký, token đã xác "
            "minh, bản ghi trong CSDL ), không phải đọc lại từ chính request. Lời gọi chỉ LỌC "
            "theo role ( `where('role', req.query.role)` ) không bị báo, vì đó không phải quyết "
            "định cấp quyền."
        ),
        remediation=(
            "Tra quyền từ phía máy chủ bằng danh tính đã xác thực: `current_user.is_admin` lấy từ "
            "CSDL, claim trong token đã xác minh chữ ký, hay giá trị trong phiên đã ký của server. "
            "Khi phải nhận quyền qua header từ gateway, hãy chắc gateway XOÁ header đó trên mọi "
            "request từ ngoài vào, và nói rõ điều đó ở nơi đọc header."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/807.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
        ),
    ),
    RuleSpec(
        id="FSB-MASS-001",
        title="Cả body của request được ghi thẳng vào đối tượng được lưu",
        category=Category.MASS_ASSIGNMENT,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-915",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Toàn bộ dữ liệu người gửi đưa lên được gán vào một đối tượng rồi lưu, không qua danh "
            "sách trường được phép: `User.objects.create(**request.POST)`, `User.create(req.body)`, "
            "`User.findByIdAndUpdate(id, req.body)`, `User::create($request->all())` hay "
            "`params.require(:user).permit!` của Rails. Người gửi chỉ cần thêm một khoá mà biểu mẫu "
            "không có -- `is_admin`, `role`, `balance`, `email_verified` -- là ghi đè được cột đó. "
            "Mức độ thiệt hại phụ thuộc vào model: trên bảng người dùng thì đây là đường lên "
            "quyền quản trị, trên một bảng không có cột nhạy cảm thì không."
        ),
        remediation=(
            "Liệt kê thẳng những trường được phép ghi: `params.require(:user).permit(:name, "
            ":email)`, `$fillable = ['name', 'email']`, `fields = ['name', 'email']` trong Meta "
            "của form, hoặc chép từng trường sang model. Rule chỉ báo chỗ THẤY request ngay tại "
            "phép ghi; một dòng cấu hình đứng riêng ( `$guarded = []`, `fields = '__all__'` ) thì "
            "không, vì nó nằm hợp lệ trong chính mã của framework. Các cột quyết định "
            "quyền và số dư phải nằm ngoài danh sách đó và chỉ đổi được qua một đường riêng có "
            "kiểm quyền."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/915.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
        ),
    ),
    RuleSpec(
        id="FSB-PATH-002",
        title="Giải nén tệp nén mà không chuẩn hoá tên thành viên ( zip slip )",
        category=Category.PATH,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-22",),
        owasp=_OWASP_ACCESS,
        description=(
            "Tên thành viên trong một tệp nén là dữ liệu của người đưa tệp lên, và nó được "
            "phép chứa `../`. Khi tên đó được nối vào thư mục đích mà không ai kiểm lại, nội "
            "dung ghi ra ngoài thư mục ấy: `../../etc/cron.d/x`, `../../.ssh/authorized_keys`, "
            "hay một tệp `.jar` của chính ứng dụng. `tarfile.extractall()` của Python không "
            "chuẩn hoá tên ( CVE-2007-4559 ), `new File(dir, entry.getName())` của Java và "
            "`filepath.Join(dest, hdr.Name)` của Go cũng không. `zipfile` của Python thì có, "
            "nên lối đó không bị báo."
        ),
        remediation=(
            "Python: truyền `filter='data'` cho `extractall` ( PEP 706 ), có từ 3.12 và được "
            "backport về 3.9.17. Java và Go: tính đường dẫn đích rồi so tiền tố -- "
            "`target.getCanonicalPath().startsWith(dir.getCanonicalPath() + File.separator)`, "
            "`strings.HasPrefix(filepath.Clean(target), filepath.Clean(dest)+string(os.PathSeparator))` "
            "-- và bỏ qua thành viên nào không khớp. Kiểm cả liên kết tượng trưng trong tệp nén."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://peps.python.org/pep-0706/",
            "https://security.snyk.io/research/zip-slip-vulnerability",
        ),
    ),
    RuleSpec(
        id="FSB-PERM-001",
        title="Quyền tệp mở cho mọi người dùng trên máy ghi",
        category=Category.PERMISSION,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe=("CWE-732", "CWE-276"),
        owasp=_OWASP_MISCONFIGURATION,
        description=(
            "`chmod 0777`, `chmod a+w`, `setWritable(true, false)` hay `umask(0)` cho bất kỳ "
            "ai có một tiến trình trên máy quyền ghi vào tệp. Nếu tệp đó là mã sẽ được chạy, "
            "một tệp cấu hình sẽ được đọc, hay một tệp log mà dịch vụ khác tin, thì đây là "
            "đường leo thang quyền cục bộ -- không cần qua mạng. Rule chỉ nhìn họ `chmod`, "
            "vì chmod bỏ qua umask nên con số viết trong mã là quyền thật; chế độ truyền cho "
            "`open` hay `mkdir` thì còn bị umask che nên không bị báo."
        ),
        remediation=(
            "Cho quyền hẹp nhất còn chạy được: 0600 cho tệp dữ liệu của một tiến trình, 0640 "
            "khi một nhóm cần đọc, 0755 cho tệp chạy được. Cần nhiều tiến trình dùng chung "
            "thì đặt nhóm chung rồi cấp quyền cho nhóm, đừng cấp cho cả máy."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/732.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        ),
    ),
    RuleSpec(
        id="FSB-TMP-001",
        title="Tệp tạm mang tên đoán trước được",
        category=Category.TEMP_FILE,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-377", "CWE-379"),
        owasp=_OWASP_MISCONFIGURATION,
        description=(
            "`/tmp` là thư mục ai cũng ghi được. Một tên tệp cố định ở đó, hay một tên do "  # NOSONAR
            "`tempfile.mktemp()` sinh ra rồi mới mở, để lại một khoảng giữa lúc chọn tên và "
            "lúc tạo tệp: ai cũng chen được vào đúng tên ấy một liên kết tượng trưng trỏ tới "
            "`~/.bashrc` hay `/etc/passwd`, và tiến trình nạn nhân ghi hộ. Đổi được nội dung "
            "tệp người khác, hoặc đọc được nội dung đáng ra là riêng."
        ),
        remediation=(
            "Dùng hàm tạo tệp tạm nguyên tử: `tempfile.NamedTemporaryFile` hay "
            "`tempfile.mkstemp` ( Python ), `Files.createTempFile` ( Java ), `os.CreateTemp` "
            "( Go ), `mkstemp` ( C ). Chúng tạo tệp với tên ngẫu nhiên và quyền chỉ chủ sở "
            "hữu trong cùng một bước, nên không còn khoảng trống nào để chen vào."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/377.html",
            "https://docs.python.org/3/library/tempfile.html#tempfile.mktemp",
        ),
    ),
    RuleSpec(
        id="FSB-DEBUG-001",
        title="Chế độ gỡ lỗi bật trong mã đi kèm ứng dụng",
        category=Category.DEBUG,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-489", "CWE-215"),
        owasp=_OWASP_MISCONFIGURATION,
        description=(
            "Bộ gỡ lỗi của Werkzeug ( `app.run(debug=True)`, `DebuggedApplication(evalex=True)` ) "
            "mở một shell Python ngay trên trang lỗi, nên nó là lối chạy mã tuỳ ý. `DEBUG = True` "
            "của Django in cấu hình, biến môi trường và truy vết của mọi request lỗi; "
            "`UseDeveloperExceptionPage()` của ASP.NET và `display_errors` của PHP cũng lộ "
            "đường dẫn, câu truy vấn và chuỗi kết nối. Rule im lặng ở nơi đây đúng là chủ ý: "
            "`app.run(debug=True)` trong `if __name__ == \"__main__\"`, tệp cấu hình có tên "
            "chứa dev / local, và `UseDeveloperExceptionPage` nằm sau `env.IsDevelopment()`."
        ),
        remediation=(
            "Lấy giá trị từ biến môi trường với mặc định là TẮT, rồi bật riêng ở máy dev: "
            "`DEBUG = os.environ.get('DEBUG') == '1'`. ASP.NET: để "
            "`UseDeveloperExceptionPage` trong nhánh `if (env.IsDevelopment())`. PHP: "
            "`display_errors = Off` kèm `log_errors = On` ở nơi triển khai."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/489.html",
            "https://werkzeug.palletsprojects.com/en/stable/debug/",
        ),
    ),
    RuleSpec(
        id="FSB-PROTO-001",
        title="Hàm gộp đối tượng ghi theo khoá của nguồn mà không loại __proto__",
        category=Category.PROTOTYPE,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe=("CWE-1321",),
        owasp=_OWASP_INTEGRITY,
        description=(
            "Một hàm gộp duyệt khoá của đối tượng nguồn rồi ghi `target[key] = ...`. Trong "
            "JavaScript, `obj['__proto__']` KHÔNG tạo một khoá tên `__proto__` mà đi thẳng "
            "vào nguyên mẫu của đối tượng, nên một nguồn chứa "
            "`{\"__proto__\": {\"isAdmin\": true}}` ghi được một thuộc tính mà MỌI đối tượng "
            "trong tiến trình đọc thấy. Hậu quả tuỳ chuỗi khai thác phía sau: vượt qua một "
            "phép kiểm đọc thuộc tính mặc định, hay bơm một tham số vào thư viện khác. Chỉ "
            "hình dạng vòng lặp thì CHƯA đủ: rule đòi thấy dữ liệu người gửi đi vào hàm gộp "
            "đó trong cùng tệp -- `merge(config, req.body)`, `JSON.parse(...)`, hoặc vòng "
            "lặp duyệt thẳng `req.body`. Không có điều kiện ấy thì mọi hàm gộp của mọi thư "
            "viện JavaScript đều bị báo, mà hầu hết chúng chỉ gộp cấu hình của chính mình."
        ),
        remediation=(
            "Bỏ qua ba khoá nguy hiểm ngay trong vòng lặp: `if (key === '__proto__' || key === "
            "'constructor' || key === 'prototype') continue;`. Chỉ nhận khoá của chính đối "
            "tượng ( `Object.prototype.hasOwnProperty.call(source, key)` ), hoặc dựng đối "
            "tượng bằng `Object.create(null)` và `Map` để không có nguyên mẫu nào mà bơm. Với "
            "dữ liệu JSON từ ngoài, dùng một lược đồ liệt kê trường được phép."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/1321.html",
            "https://portswigger.net/web-security/prototype-pollution",
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
