#!/usr/bin/env python3
"""Đo tỉ lệ báo nhầm của bộ phân tích tệp thực thi trên MÁY CỦA ANH EM.

Con số trong README được đo bằng đúng script này. Nó không thể chạy trong CI
như một bài kiểm tra, vì bộ tệp lành ở đây là phần mềm đã cài trên máy, mỗi
máy một khác - nên cách trung thực duy nhất là nói rõ lệnh và để anh em tự
chạy lại trên máy mình.

    python tools/measure_binary_corpus.py /usr/bin /usr/sbin
    python tools/measure_binary_corpus.py "C:/Windows/System32" --max-files 3000

Mọi tệp được gắn cờ đều được in ra kèm dấu hiệu, để xem từng cái một: đó là
cách tìm ra dấu hiệu nào đang quá rộng.
"""

from __future__ import annotations

import argparse
import collections
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fortress_scan.binary import engine  # noqa: E402
from fortress_scan.binary.model import Tier, Verdict  # noqa: E402


def measure(roots, max_files: int, max_mb: int):
    verdicts: "collections.Counter[str]" = collections.Counter()
    families: "collections.Counter[str]" = collections.Counter()
    indicators: "collections.Counter[str]" = collections.Counter()
    flagged = []
    failures = []
    files = 0
    total_bytes = 0
    started = time.time()
    for root in roots:
        for path in engine.discover(root, max_files):
            try:
                report = engine.analyze_path(str(path), max_mb << 20)
            except OSError:
                continue
            except Exception as exc:  # một tệp hỏng không được dừng phép đo
                failures.append((str(path), "%s: %s" % (type(exc).__name__, exc)))
                continue
            files += 1
            total_bytes += report.size
            verdicts[report.verdict.key] += 1
            families[report.parsed.family] += 1
            for hit in report.hits:
                indicators["%s (%s)" % (hit.spec.id, hit.tier.key)] += 1
            if report.verdict >= Verdict.LOW:
                flagged.append(
                    (
                        report.verdict,
                        str(path),
                        [hit.spec.id for hit in report.hits if hit.tier >= Tier.SUSPICIOUS],
                    )
                )
    return {
        "files": files,
        "megabytes": total_bytes >> 20,
        "seconds": time.time() - started,
        "verdicts": verdicts,
        "families": families,
        "indicators": indicators,
        "flagged": flagged,
        "failures": failures,
    }


def render(result) -> str:
    lines = [
        "đã phân tích %d tệp ( %d MB ) trong %.1fs"
        % (result["files"], result["megabytes"], result["seconds"]),
        "định dạng: %s"
        % ", ".join("%s %d" % (key, value) for key, value in sorted(result["families"].items())),
        "",
        "kết luận:",
    ]
    for verdict in sorted(Verdict, reverse=True):
        count = result["verdicts"].get(verdict.key, 0)
        share = (100.0 * count / result["files"]) if result["files"] else 0.0
        lines.append("  %-11s %6d  %5.2f%%" % (verdict.key, count, share))
    above = sum(
        result["verdicts"].get(verdict.key, 0)
        for verdict in (Verdict.SUSPICIOUS, Verdict.LIKELY, Verdict.HIGH)
    )
    lines += [
        "",
        "từ mức 'suspicious' trở lên: %d tệp. Trên một bộ tệp LÀNH, mỗi tệp ở đây là một"
        % above,
        "lần báo nhầm, nên hãy xem từng cái.",
        "",
        "dấu hiệu hay gặp nhất:",
    ]
    for name, count in result["indicators"].most_common(15):
        lines.append("  %-24s %6d" % (name, count))
    if result["flagged"]:
        lines += ["", "các tệp bị gắn cờ:"]
        for verdict, path, serious in sorted(result["flagged"], key=lambda row: -int(row[0])):
            lines.append("  %-11s %s %s" % (verdict.key, path, ", ".join(serious)))
    if result["failures"]:
        lines += ["", "tệp làm parser ném lỗi ( đây là lỗi của công cụ, xin báo lại ):"]
        for path, message in result["failures"]:
            lines.append("  %s: %s" % (path, message))
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("roots", nargs="+", help="thư mục chứa phần mềm lành để đo")
    parser.add_argument("--max-files", type=int, default=20_000)
    parser.add_argument("--max-mb", type=int, default=64, help="trần đọc mỗi tệp")
    arguments = parser.parse_args(argv)
    sys.stdout.write(render(measure(arguments.roots, arguments.max_files, arguments.max_mb)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
