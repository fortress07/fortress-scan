"""Ngữ cảnh tệp: phân loại theo đường dẫn và phép hạ độ tin cậy đi kèm.

Đây là bộ giảm false positive rẻ nhất mà công cụ có, nên nó cũng là chỗ dễ
gây hại nhất nếu sai: phân loại nhầm một tệp sản phẩm thành "test" là tự tay
hạ mức một lỗ hổng thật. Những kiểm tra ở đây khoá lại cả hai phía -- cái gì
phải bị hạ, và quan trọng hơn, cái gì KHÔNG được đụng tới.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.context import classify
from fortress_scan.core.engine import scan
from fortress_scan.core.model import Confidence, PathContext

VULN = (
    "import os\n"
    "from flask import request\n"
    "def h():\n"
    "    os.system('ping ' + request.args['a'])\n"
)


@pytest.mark.parametrize(
    "relative,expected",
    [
        ("app/views.py", PathContext.PRODUCTION),
        ("src/fortress_scan/cli.py", PathContext.PRODUCTION),
        ("main.py", PathContext.PRODUCTION),
        ("tests/test_api.py", PathContext.TEST),
        ("app/models_test.go", PathContext.TEST),
        ("src/Widget.spec.ts", PathContext.TEST),
        ("conftest.py", PathContext.TEST),
        ("src/UserServiceTest.java", PathContext.TEST),
        ("src/PaymentIT.java", PathContext.TEST),
        ("src/it/java/app/RegistrationUITest.java", PathContext.TEST),
        ("src/APITests.java", PathContext.TEST),
        ("spec.rb", PathContext.TEST),
        ("pkg/fixtures/payload.py", PathContext.TEST),
        ("examples/demo.js", PathContext.EXAMPLE),
        ("docs/conf.py", PathContext.DOCUMENTATION),
        ("proto/user_pb2.py", PathContext.GENERATED),
        ("static/app.min.js", PathContext.GENERATED),
        ("third_party/lib/a.py", PathContext.VENDORED),
    ],
)
def test_classification(relative: str, expected: PathContext):
    assert classify(relative) is expected


@pytest.mark.parametrize(
    "relative",
    [
        # Khớp theo TỪNG THÀNH PHẦN đường dẫn, không phải chuỗi con: ba cái tên
        # này đều chứa một từ khoá phân loại nhưng không thuộc về nó.
        "contest/app.py",
        "sample_rate.py",
        "app/protest.py",
        "src/latest.py",
        "documentation_builder.py",
        "src/SPLIT.java",
        "src/LATEST.java",
    ],
)
def test_lookalike_names_stay_production(relative: str):
    assert classify(relative) is PathContext.PRODUCTION


def test_empty_and_odd_paths_do_not_raise():
    for relative in ("", ".", "/", "//", "\\", "a//b.py"):
        assert isinstance(classify(relative), PathContext)


def test_vendor_wins_over_test_inside_it():
    """`vendor/x/tests/` vẫn là mã đi mượn: người dùng không sửa được nó."""
    assert classify("vendor/pkg/tests/thing.py") is PathContext.VENDORED


def _scan_tree(tmp_path: Path, relative: str, config: Config = None):
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(VULN, encoding="utf-8")
    return scan(str(tmp_path), config or Config())


def test_production_finding_keeps_its_confidence(tmp_path: Path):
    result = _scan_tree(tmp_path, "app/api.py")
    assert result.findings
    finding = result.findings[0]
    assert finding.confidence is Confidence.HIGH
    assert finding.context is PathContext.PRODUCTION


def test_test_file_finding_is_demoted_exactly_one_step(tmp_path: Path):
    result = _scan_tree(tmp_path, "tests/test_api.py")
    assert result.findings
    finding = result.findings[0]
    assert finding.confidence is Confidence.MEDIUM
    assert finding.context is PathContext.TEST
    assert "context:test" in finding.tags


def test_demotion_never_hides_the_finding(tmp_path: Path):
    """Hạ mức KHÔNG phải là xoá: phát hiện vẫn phải có mặt trong báo cáo."""
    result = _scan_tree(tmp_path, "examples/demo.py")
    assert [f.rule_id for f in result.findings] == ["FSB-CMD-001"]


def test_demotion_can_be_turned_off(tmp_path: Path):
    result = _scan_tree(tmp_path, "tests/test_api.py", Config(context_awareness=False))
    assert result.findings
    assert result.findings[0].confidence is Confidence.HIGH
    # Nhãn ngữ cảnh vẫn còn: tắt hiệu chỉnh là tắt phép HẠ MỨC, không phải
    # tắt việc nói ra tệp này nằm ở đâu.
    assert "context:test" in result.findings[0].tags


def test_demoted_finding_says_why(tmp_path: Path):
    result = _scan_tree(tmp_path, "tests/test_api.py")
    evidence = " ".join(result.findings[0].evidence)
    assert "hạ một nấc" in evidence


def test_min_confidence_is_applied_after_demotion(tmp_path: Path):
    """Ngưỡng lọc phải soi con số CUỐI CÙNG.

    FindingBuilder so ngưỡng với độ tin cậy trước hiệu chỉnh, nên nếu pha
    hiệu chỉnh không lọc lại thì --min-confidence=high vẫn để lọt một phát
    hiện vừa bị hạ xuống medium -- người dùng đặt ngưỡng mà nhận về thứ nằm
    dưới ngưỡng.
    """
    result = _scan_tree(tmp_path, "tests/test_api.py", Config(min_confidence=Confidence.HIGH))
    assert result.findings == []
