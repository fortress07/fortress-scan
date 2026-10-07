"""Dòng lệnh: ``fortress-scan binary <tệp hoặc thư mục>``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from .. import __version__
from ..security import paths as safe_paths
from ..security import runtime as sandbox
from ..security import text as safe_text
from . import engine, report
from .model import TriageReport, Verdict

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3

_VERDICTS = {verdict.key: verdict for verdict in Verdict if verdict is not Verdict.NONE}


def _stderr(message: str) -> None:
    sys.stderr.write(safe_text.neutralize(message) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fortress-scan binary",
        description=(
            "( beta ) Phân tích TĨNH tệp thực thi ( PE, .NET, ELF, Mach-O, JAR, script ) để tìm dấu "
            "hiệu ransomware. Không bao giờ chạy, nạp hay gửi tệp đi đâu."
        ),
        epilog="Mã thoát: 0 dưới ngưỡng --fail-on, 1 có tệp đạt ngưỡng, 2 sai cách dùng, 3 lỗi nội bộ.",
    )
    parser.add_argument("target", help="tệp hoặc thư mục cần phân tích")
    parser.add_argument("-f", "--format", choices=("console", "json", "markdown"), default="console")
    parser.add_argument("-o", "--output", help="ghi báo cáo ra tệp thay vì in ra màn hình")
    parser.add_argument("-v", "--verbose", action="store_true", help="hiện mọi dấu hiệu, giải thích và cách khắc phục")
    parser.add_argument("--no-color", action="store_true", help="tắt màu ANSI")
    parser.add_argument("--quiet", action="store_true", help="không in báo cáo, chỉ lấy mã thoát")
    parser.add_argument(
        "--fail-on",
        choices=sorted(_VERDICTS, key=lambda key: _VERDICTS[key]),
        default="suspicious",
        help="thoát 1 khi có tệp đạt mức này (mặc định: suspicious)",
    )
    parser.add_argument("--exit-zero", action="store_true", help="luôn thoát 0")
    parser.add_argument(
        "--max-size",
        type=int,
        metavar="MB",
        default=engine.DEFAULT_MAX_BYTES >> 20,
        help="chỉ đọc tối đa từng này MB mỗi tệp (mặc định: %(default)s)",
    )
    parser.add_argument(
        "--max-files", type=int, default=engine.MAX_DIRECTORY_FILES, help="trần số tệp khi quét thư mục"
    )
    parser.add_argument(
        "--only-flagged",
        action="store_true",
        help="khi quét thư mục, chỉ in tệp có kết luận từ mức 'đáng ngờ' trở lên",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    sandbox.engage()
    for warning in sandbox.elevated_privilege_warnings():
        _stderr("fortress-scan: cảnh báo: %s" % warning)
    if args.max_size < 1 or args.max_files < 1:
        _stderr("fortress-scan: --max-size và --max-files phải là số dương")
        return EXIT_USAGE
    target = Path(args.target)
    if not target.exists():
        _stderr("fortress-scan: không tìm thấy: %s" % args.target)
        return EXIT_USAGE
    output_path = None
    if args.output:
        try:
            output_path = safe_paths.validate_output_path(args.output)
        except safe_paths.PathConfinementError as exc:
            _stderr("fortress-scan: %s" % exc)
            return EXIT_USAGE

    reports: List[TriageReport] = []
    try:
        for path in engine.discover(str(target), args.max_files):
            try:
                reports.append(engine.analyze_path(str(path), args.max_size << 20))
            except OSError as exc:
                _stderr("fortress-scan: không đọc được %s: %s" % (path, exc))
    except KeyboardInterrupt:
        _stderr("fortress-scan: đã dừng theo yêu cầu")
        return EXIT_INTERNAL
    except Exception as exc:
        _stderr("fortress-scan: lỗi nội bộ: %s: %s" % (type(exc).__name__, exc))
        return EXIT_INTERNAL

    shown = reports
    if args.only_flagged and target.is_dir():
        shown = [r for r in reports if r.verdict >= Verdict.SUSPICIOUS]
    if not reports and not args.quiet:
        _stderr("fortress-scan: không tìm thấy tệp thực thi nào để phân tích")

    if args.format == "json":
        payload = report.to_json(shown, __version__)
    elif args.format == "markdown":
        payload = report.to_markdown(shown, __version__)
    else:
        color = output_path is None and not args.no_color and hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        payload = report.console(shown, color=color, verbose=args.verbose)
    try:
        if output_path is not None:
            output_path.write_text(payload, encoding="utf-8")
            if not args.quiet:
                _stderr("fortress-scan: đã ghi báo cáo vào %s" % output_path)
        elif not args.quiet or args.format != "console":
            sys.stdout.write(payload)
    except OSError as exc:
        _stderr("fortress-scan: không ghi được báo cáo: %s" % exc)
        return EXIT_USAGE

    if args.exit_zero:
        return EXIT_CLEAN
    threshold = _VERDICTS[args.fail_on]
    return EXIT_FINDINGS if any(r.verdict >= threshold for r in reports) else EXIT_CLEAN
