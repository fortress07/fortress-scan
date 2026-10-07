"""Hình trong README không được cũ hơn mã sinh ra nó.

Hình minh hoạ có một kiểu hỏng rất êm: ai đó thêm một rule, con số trong
`core.registry` đổi, còn tấm SVG đã commit thì vẫn nói con số cũ. Không ai
nhận ra, vì hình vẫn hiện ra bình thường và vẫn đẹp.

Nên hình được SINH ra chứ không vẽ tay, và bài kiểm tra này chạy lại đúng bộ
sinh đó rồi so từng byte với tệp đang nằm trong repo. Lệch một byte là hỏng,
kèm hướng dẫn chạy lại.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GENERATOR = ROOT / "tools" / "generate_diagrams.py"
IMG = ROOT / "docs" / "img"

REGENERATE = "chạy lại: python tools/generate_diagrams.py"


def _load_generator():
    spec = importlib.util.spec_from_file_location("fs_generate_diagrams", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generated():
    return _load_generator().build()


def test_generator_exists():
    assert GENERATOR.is_file(), "thiếu tools/generate_diagrams.py"


def test_every_generated_file_is_committed(generated):
    missing = sorted(name for name in generated if not (IMG / name).is_file())
    assert missing == [], "thiếu tệp hình trong repo: %s; %s" % (missing, REGENERATE)


def test_no_stale_files_left_behind(generated):
    on_disk = {path.name for path in IMG.glob("*.svg")}
    extra = sorted(on_disk - set(generated))
    assert extra == [], "hình thừa không còn được sinh ra nữa: %s" % extra


def test_committed_svg_matches_a_fresh_run(generated):
    """Đây là phép kiểm chính: nội dung phải khớp từng byte."""
    stale = []
    for name, content in sorted(generated.items()):
        path = IMG / name
        if not path.is_file():
            continue
        if path.read_text(encoding="utf-8") != content:
            stale.append(name)
    assert stale == [], "hình đã cũ so với mã: %s; %s" % (stale, REGENERATE)


def test_every_diagram_has_both_themes(generated):
    """Thiếu một bản là README hỏng ở đúng chế độ màu kia của người đọc."""
    stems = {name.rsplit("-", 1)[0] for name in generated}
    for stem in sorted(stems):
        for theme in ("light", "dark"):
            assert "%s-%s.svg" % (stem, theme) in generated, (stem, theme)


def test_rule_counts_on_the_diagrams_come_from_the_registry(generated):
    """Con số trên hình phải là con số thật, không phải hằng chép tay."""
    from fortress_scan.core.registry import all_rules

    total = len(list(all_rules()))
    rules_svg = generated["rules-light.svg"]
    assert "%d rule" % total in rules_svg, (
        "hình bộ rule không nhắc tới tổng %d rule; %s" % (total, REGENERATE)
    )


def test_readme_points_at_files_that_exist():
    """Liên kết hình gãy thì trên GitHub chỉ còn một ô ảnh vỡ."""
    import re

    text = (ROOT / "README.md").read_text(encoding="utf-8")
    referenced = set(re.findall(r'(?:src|srcset)="(docs/img/[^"]+)"', text))
    assert referenced, "README không nhúng hình nào"
    broken = sorted(ref for ref in referenced if not (ROOT / ref).is_file())
    assert broken == [], "README trỏ tới hình không tồn tại: %s" % broken


def test_readme_offers_a_dark_variant_for_every_embedded_image():
    """Mỗi hình nhúng phải đi theo cặp sáng/tối, kẻo chế độ tối đọc không ra."""
    import re

    text = (ROOT / "README.md").read_text(encoding="utf-8")
    light = {
        ref for ref in re.findall(r'src="(docs/img/[^"]+)"', text)
        if ref.endswith("-light.svg")
    }
    dark = set(re.findall(r'srcset="(docs/img/[^"]+)"', text))
    missing = sorted(
        ref for ref in light if ref.replace("-light.svg", "-dark.svg") not in dark
    )
    assert missing == [], "những hình này thiếu bản tối trong README: %s" % missing


def test_binary_indicator_counts_on_the_diagram_come_from_the_catalogue(generated):
    """Hình nói bao nhiêu dấu hiệu thì phải đúng bằng số dấu hiệu đang có."""
    import collections

    from fortress_scan.binary.catalogue import SPECS

    counts = collections.Counter(spec.category for spec in SPECS.values())
    svg = generated["binary-triage-light.svg"]
    assert "%d dấu hiệu, " % len(SPECS) in svg, (
        "hình không nhắc tới tổng %d dấu hiệu; %s" % (len(SPECS), REGENERATE)
    )
    for category, count in sorted(counts.items()):
        assert "%d dấu hiệu" % count in svg, (category, count, REGENERATE)


def test_the_score_bands_on_the_diagram_come_from_the_scorer(generated):
    """Đổi ngưỡng điểm mà quên vẽ lại thì hình nói sai thang kết luận."""
    from fortress_scan.binary.scoring import BANDS

    svg = generated["binary-triage-light.svg"]
    for low, high in BANDS.values():
        assert ">%d-%d<" % (low, high) in svg, (low, high, REGENERATE)
