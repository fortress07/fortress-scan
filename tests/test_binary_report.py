"""Báo cáo và dòng lệnh: nói đủ, nói thật, và không bao giờ nói quá.

Một báo cáo triage là thứ người phòng thủ đọc lúc đang gấp. Nên ngoài tính
đúng, nó còn phải chịu được một chi tiết bẩn: tên tệp và chuỗi bên trong tệp
đều do kẻ tấn công đặt, và chúng đi thẳng ra terminal. Một chuỗi thoát ANSI
trong đó viết lại được những dòng đã in - kể cả dòng kết luận.
"""

from __future__ import annotations

import json
import sys

import pytest

import binary_builders as B
from fortress_scan import cli as main_cli
from fortress_scan.binary import cli as binary_cli
from fortress_scan.binary import engine, report
from fortress_scan.binary.model import Tier, Verdict
from fortress_scan.security.text import BIDI_CONTROLS

from test_binary_indicators import benign_packed_installer_pe, ransom_shaped_pe

VERSION = "0.1.0"


def _report(data=None, name="mau.exe"):
    return engine.analyze_bytes(data if data is not None else ransom_shaped_pe(), name)


# -------------------------------------------------------------------- console


def test_console_report_leads_with_the_verdict_and_names_its_evidence():
    text = report.console([_report()], color=False, verbose=True)
    assert "dấu hiệu ransomware rõ rệt" in text
    assert "FSX-C05" in text and "FSX-T01" in text
    assert "vssadmin" in text
    assert "ATT&CK T1490" in text
    assert "lành tính có thể:" in text, "mỗi dấu hiệu phải kèm giải thích lành tính"
    assert "khắc phục:" in text


def test_console_report_hides_context_indicators_until_verbose():
    quiet = report.console([_report(B.build_pe(imports={"kernel32.dll": ["FindFirstFileW"]}))], verbose=False)
    loud = report.console([_report(B.build_pe(imports={"kernel32.dll": ["FindFirstFileW"]}))], verbose=True)
    assert "dấu hiệu bối cảnh được ẩn" in quiet
    assert "FSX-C01" in loud
    assert "FSX-C01" not in quiet


def test_console_report_always_ends_with_the_beta_caveat():
    for data, name in ((ransom_shaped_pe(), "mau.exe"), (B.build_pe(), "hello.exe")):
        text = report.console([_report(data, name)])
        assert "phân tích TĨNH ở bản beta" in text
        assert "không phải phán quyết tuyệt đối" in text


def test_console_report_summarises_when_several_files_are_analysed():
    reports = [_report(), _report(B.build_pe(), "hello.exe")]
    text = report.console(reports)
    assert "Tổng cộng 2 tệp" in text
    assert "dấu hiệu ransomware rõ rệt" in text


@pytest.mark.parametrize(
    "hostile",
    [
        "mau\x1b[2K\x1b[1A FAKE: khong co dau hieu .exe",
        "mau%s.exe" % BIDI_CONTROLS[4],
        "mau\r\n  [OK] sach .exe",
        "mau\x00.exe",
    ],
)
def test_a_hostile_file_name_cannot_rewrite_the_console_report(hostile):
    """Tên tệp do kẻ tấn công đặt. Nó không được chứa byte điều khiển thật.

    Một `\\x1b[1A` trong tên tệp xoá được dòng kết luận vừa in ra và thay bằng
    một dòng do kẻ tấn công soạn.
    """
    text = report.console([_report(B.build_pe(), hostile)], color=False, verbose=True)
    for forbidden in ("\x1b", "\x00", "\r", BIDI_CONTROLS[4]):
        assert forbidden not in text
    assert "\\x1b" in text or "\\x00" in text or "\\x0d" in text or "\\u202e" in text


def test_hostile_strings_inside_the_file_are_neutralised_too():
    body = b"\x1b[2K\x1b[1A  [OK] khong co dau hieu\x00" + ("ngược%s" % BIDI_CONTROLS[4]).encode("utf-8")
    data = B.build_pe(
        sections=[
            B.PeSection(".text", b"\xc3" * 16, B.TEXT_FLAGS),
            B.PeSection(".rdata", body, B.RDATA_FLAGS),
        ]
    )
    text = report.console([_report(data, "mau.exe")], color=False, verbose=True)
    assert "\x1b" not in text
    assert BIDI_CONTROLS[4] not in text


def test_console_colour_is_only_emitted_when_asked_for():
    plain = report.console([_report()], color=False)
    tinted = report.console([_report()], color=True)
    assert "\x1b[" not in plain
    assert "\x1b[" in tinted


def test_console_names_the_signature_as_unverified():
    """Có chữ ký KHÔNG phải là chữ ký hợp lệ.

    Công cụ không kiểm chuỗi tin cậy, nên nó phải nói ra chỗ đó, kẻo người
    đọc hiểu ngược.
    """
    signed = _report(
        B.build_pe(certificate=b"\x30\x82" + b"\x06\x03\x55\x04\x03\x0c\x04Acme"), "ok.exe"
    )
    text = report.console([signed])
    assert "CHƯA kiểm tính hợp lệ" in text
    assert "Acme" in text
    assert "chữ ký: không có" in report.console([_report(B.build_pe(), "x.exe")])


# ----------------------------------------------------------------------- JSON


def test_json_report_is_valid_and_carries_evidence_and_remediation():
    payload = json.loads(report.to_json([_report()], VERSION))
    assert payload["beta"] is True
    assert payload["schema"] == report.SCHEMA_VERSION
    assert payload["version"] == VERSION
    entry = payload["files"][0]
    assert entry["verdict"] == "high"
    assert 85 <= entry["score"] <= 100
    assert entry["hashes"]["sha256"]
    identifiers = {item["id"]: item for item in entry["indicators"]}
    assert "FSX-C05" in identifiers
    rule = identifiers["FSX-C05"]
    assert rule["tier"] == "strong"
    assert rule["evidence"] and rule["evidence"][0]["detail"]
    assert rule["benign_explanations"] and rule["remediation"]
    assert rule["attack"] == ["T1490"]
    assert entry["guidance"] and entry["limitations"]
    assert entry["iocs"]


def test_json_report_never_claims_a_verified_signature():
    payload = json.loads(
        report.to_json([_report(B.build_pe(certificate=b"\x30\x82" + b"\x00" * 32), "ok.exe")], VERSION)
    )
    signature = payload["files"][0]["format"]["signature"]
    assert signature["present"] is True
    assert signature["verified"] is False


def test_json_report_hides_internal_metadata_keys():
    """Khoá nội bộ ( tiền tố _ ) là chi tiết cài đặt, không phải dữ liệu báo cáo."""
    payload = json.loads(
        report.to_json([_report(B.build_pe(certificate=b"\x30\x82" + b"\x00" * 32), "ok.exe")], VERSION)
    )
    assert all(not key.startswith("_") for key in payload["files"][0]["format"]["metadata"])


def test_json_report_matches_the_hashes_of_the_bytes_on_disk():
    import hashlib

    data = ransom_shaped_pe()
    payload = json.loads(report.to_json([_report(data)], VERSION))
    assert payload["files"][0]["hashes"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert payload["files"][0]["size"] == len(data)


def test_json_report_survives_hostile_bytes_in_names_and_strings():
    hostile = "mau\x1b[2K%s.exe" % BIDI_CONTROLS[4]
    text = report.to_json([_report(B.build_pe(), hostile)], VERSION)
    assert "\x1b" not in text, "json.dumps phải escape, không được để byte thật đi qua"
    assert json.loads(text)["files"][0]["path"] == hostile


def test_json_section_entropy_is_rounded_but_not_rewritten():
    data = B.build_pe(sections=[B.PeSection(".text", bytes(range(256)) * 8, B.TEXT_FLAGS)])
    result = _report(data, "x.exe")
    payload = json.loads(report.to_json([result], VERSION))
    assert payload["files"][0]["format"]["sections"][0]["entropy"] == pytest.approx(
        round(result.parsed.sections[0].entropy, 3)
    )


# ------------------------------------------------------------------- markdown


def test_markdown_report_has_a_summary_table_and_a_section_per_file():
    text = report.to_markdown([_report(), _report(B.build_pe(), "hello.exe")], VERSION)
    assert text.startswith("# Báo cáo phân tích file thực thi ( beta )")
    assert "| Tệp | Kết luận |" in text
    assert "## `mau.exe`" in text and "## `hello.exe`" in text
    assert "**Nên làm**" in text and "**Giới hạn**" in text


def test_markdown_escapes_table_breaking_characters():
    hostile = "mau|pipe<script>.exe"
    text = report.to_markdown([_report(B.build_pe(), hostile)], VERSION)
    assert "mau\\|pipe&lt;script&gt;.exe" in text
    assert "<script>" not in text


def test_markdown_lists_remediation_only_for_indicators_that_matter():
    text = report.to_markdown([_report()], VERSION)
    assert "**Khắc phục theo từng dấu hiệu**" in text
    clean = report.to_markdown([_report(B.build_pe(), "hello.exe")], VERSION)
    assert "**Khắc phục theo từng dấu hiệu**" not in clean


# -------------------------------------------------------------------- CLI


def test_cli_exit_code_is_one_when_a_file_reaches_the_threshold(tmp_path, capsys):
    target = tmp_path / "mau.exe"
    target.write_bytes(ransom_shaped_pe())
    assert binary_cli.main([str(target)]) == binary_cli.EXIT_FINDINGS
    assert "dấu hiệu ransomware rõ rệt" in capsys.readouterr().out


def test_cli_exit_code_is_zero_for_a_clean_file(tmp_path, capsys):
    target = tmp_path / "hello.exe"
    target.write_bytes(B.build_pe())
    assert binary_cli.main([str(target)]) == binary_cli.EXIT_CLEAN
    assert "không thấy dấu hiệu ransomware" in capsys.readouterr().out


def test_cli_threshold_is_configurable(tmp_path, capsys):
    target = tmp_path / "setup.exe"
    target.write_bytes(benign_packed_installer_pe())
    assert binary_cli.main([str(target), "--quiet"]) == binary_cli.EXIT_CLEAN
    assert binary_cli.main([str(target), "--quiet", "--fail-on", "low"]) == binary_cli.EXIT_FINDINGS
    capsys.readouterr()


def test_cli_exit_zero_always_wins(tmp_path, capsys):
    target = tmp_path / "mau.exe"
    target.write_bytes(ransom_shaped_pe())
    assert binary_cli.main([str(target), "--exit-zero", "--quiet"]) == binary_cli.EXIT_CLEAN
    capsys.readouterr()


def test_cli_quiet_prints_nothing_but_still_writes_machine_formats(tmp_path, capsys):
    target = tmp_path / "mau.exe"
    target.write_bytes(ransom_shaped_pe())
    binary_cli.main([str(target), "--quiet"])
    assert capsys.readouterr().out == ""
    binary_cli.main([str(target), "--quiet", "--format", "json"])
    assert json.loads(capsys.readouterr().out)["files"]


def test_cli_rejects_a_missing_target(tmp_path, capsys):
    assert binary_cli.main([str(tmp_path / "khong-co.exe")]) == binary_cli.EXIT_USAGE
    assert "không tìm thấy" in capsys.readouterr().err


def test_cli_rejects_nonsense_limits(tmp_path, capsys):
    target = tmp_path / "a.exe"
    target.write_bytes(B.build_pe())
    assert binary_cli.main([str(target), "--max-size", "0"]) == binary_cli.EXIT_USAGE
    assert binary_cli.main([str(target), "--max-files", "0"]) == binary_cli.EXIT_USAGE
    capsys.readouterr()


def test_cli_writes_the_report_to_a_file_when_asked(tmp_path, capsys):
    target = tmp_path / "mau.exe"
    target.write_bytes(ransom_shaped_pe())
    output = tmp_path / "bao-cao.json"
    binary_cli.main([str(target), "--format", "json", "--output", str(output)])
    assert json.loads(output.read_text(encoding="utf-8"))["files"][0]["verdict"] == "high"
    assert capsys.readouterr().out == ""


def test_cli_refuses_to_write_through_a_link(tmp_path, capsys):
    target = tmp_path / "mau.exe"
    target.write_bytes(B.build_pe())
    victim = tmp_path / "that.json"
    victim.write_text("giu nguyen", encoding="utf-8")
    link = tmp_path / "lien-ket.json"
    try:
        link.symlink_to(victim)
    except (OSError, NotImplementedError):
        pytest.skip("hệ thống không cho tạo liên kết")
    assert binary_cli.main([str(target), "--output", str(link)]) == binary_cli.EXIT_USAGE
    assert victim.read_text(encoding="utf-8") == "giu nguyen"
    assert "liên kết" in capsys.readouterr().err


def test_cli_scans_a_directory_and_can_show_only_flagged_files(tmp_path, capsys):
    (tmp_path / "mau.exe").write_bytes(ransom_shaped_pe())
    (tmp_path / "hello.exe").write_bytes(B.build_pe())
    assert binary_cli.main([str(tmp_path)]) == binary_cli.EXIT_FINDINGS
    full = capsys.readouterr().out
    assert "mau.exe" in full and "hello.exe" in full

    binary_cli.main([str(tmp_path), "--only-flagged"])
    trimmed = capsys.readouterr().out
    assert "mau.exe" in trimmed and "hello.exe" not in trimmed


def test_cli_says_so_when_a_directory_holds_no_executable(tmp_path, capsys):
    (tmp_path / "ghi-chu.txt").write_text("xin chao", encoding="utf-8")
    assert binary_cli.main([str(tmp_path)]) == binary_cli.EXIT_CLEAN
    assert "không tìm thấy tệp thực thi" in capsys.readouterr().err


def test_the_main_command_dispatches_the_binary_subcommand(tmp_path, capsys):
    """`fortress-scan binary ...` phải tới đúng bộ phân tích tệp thực thi,
    chứ không bị argparse của lệnh chính hiểu thành đường dẫn cần quét."""
    target = tmp_path / "mau.exe"
    target.write_bytes(ransom_shaped_pe())
    assert main_cli.main(["binary", str(target), "--quiet"]) == binary_cli.EXIT_FINDINGS
    capsys.readouterr()

    assert main_cli.main(["binary", str(target), "--format", "json", "--quiet"]) == 1
    assert json.loads(capsys.readouterr().out)["files"][0]["verdict"] == "high"


def test_the_main_command_help_mentions_the_beta_subcommand(capsys):
    parser = main_cli.build_parser()
    assert "binary" in parser.format_help()


def test_binary_module_can_be_run_as_a_module():
    import importlib

    module = importlib.import_module("fortress_scan.binary.__main__")
    assert hasattr(module, "main")


def test_tier_and_verdict_labels_are_all_translated():
    for tier in Tier:
        assert tier.label and tier.key
    for verdict in Verdict:
        assert verdict.label and verdict.key
        assert verdict.label != verdict.key


def test_console_report_of_a_truncated_read_says_so(tmp_path):
    target = tmp_path / "lon.exe"
    target.write_bytes(ransom_shaped_pe())
    result = engine.analyze_path(str(target), 2048)
    text = report.console([result], verbose=True)
    assert "trần đọc" in text


def test_report_functions_accept_an_empty_list():
    assert "Tổng cộng" not in report.console([])
    assert json.loads(report.to_json([], VERSION))["files"] == []
    assert "| Tệp |" in report.to_markdown([], VERSION)


@pytest.mark.skipif(sys.platform == "win32", reason="quyền tệp trên Windows khác hẳn")
def test_cli_reports_an_unreadable_file_without_dying(tmp_path, capsys):
    import os

    target = tmp_path / "chan.exe"
    target.write_bytes(B.build_pe())
    target.chmod(0o000)
    try:
        if os.access(str(target), os.R_OK):
            pytest.skip("đang chạy bằng quyền bỏ qua phân quyền tệp")
        assert binary_cli.main([str(target)]) == binary_cli.EXIT_CLEAN
        assert "không đọc được" in capsys.readouterr().err
    finally:
        target.chmod(0o644)
