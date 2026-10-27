#!/usr/bin/env python3
"""Đo độ chính xác của fortress-scan trên corpus ba tầng, bằng một lệnh.

    python tools/benchmark.py                 # cả ba tầng trong tests/corpus
    python tools/benchmark.py --tier 2        # chỉ một tầng
    python tools/benchmark.py --json out.json --show-misses

Corpus nằm trong tests/corpus và chạy hoàn toàn offline. Kỳ vọng được ghi
ngay trên dòng có lỗi:

    db.query("... " + req.query.name)   // fsb-expect: FSB-SQL-001

Dòng không có `fsb-expect` mà vẫn bị báo là dương tính giả. `fsb-allow: RULE`
đánh dấu một gợi ý kiểm tra hợp lệ trên dòng an toàn ( ví dụ FSB-SQL-002 cho
câu SQL dựng động từ hằng ): nó không tính là đúng mà cũng không tính là sai.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fortress_scan.core.config import Config  # noqa: E402
from fortress_scan.core.engine import scan  # noqa: E402

CORPUS = ROOT / "tests" / "corpus"
MARK_EXPECT = "fsb-expect:"
MARK_ALLOW = "fsb-allow:"
_MAX_MARKER_FILE = 2_000_000

Key = Tuple[str, int, str]


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    neutral: int = 0
    untriaged: int = 0
    seconds: float = 0.0
    files: int = 0
    false_positives: List[Key] = field(default_factory=list)
    false_negatives: List[Key] = field(default_factory=list)

    @property
    def precision(self) -> float:
        flagged = self.tp + self.fp + self.untriaged
        return self.tp / flagged if flagged else 1.0

    @property
    def recall(self) -> float:
        wanted = self.tp + self.fn
        return self.tp / wanted if wanted else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    def add(self, other: "Score") -> None:
        self.tp += other.tp
        self.fp += other.fp
        self.fn += other.fn
        self.neutral += other.neutral
        self.untriaged += other.untriaged
        self.seconds += other.seconds
        self.files += other.files
        self.false_positives.extend(other.false_positives)
        self.false_negatives.extend(other.false_negatives)

    def as_dict(self) -> Dict[str, object]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "neutral": self.neutral,
            "untriaged": self.untriaged,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "seconds": round(self.seconds, 2),
            "files": self.files,
            "false_positives": ["%s:%d %s" % key for key in sorted(self.false_positives)],
            "false_negatives": ["%s:%d %s" % key for key in sorted(self.false_negatives)],
        }


# --------------------------------------------------------------- markers
def _rules_after(line: str, marker: str) -> List[str]:
    position = line.find(marker)
    if position < 0:
        return []
    tail = line[position + len(marker) :].replace(",", " ")
    rules = []
    for word in tail.split():
        if word.startswith("FSB-"):
            rules.append(word.rstrip("*/-#>;"))
        else:
            break
    return rules


def parse_markers(root: Path) -> Tuple[Set[Key], Set[Key]]:
    expected: Set[Key] = set()
    allowed: Set[Key] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.stat().st_size > _MAX_MARKER_FILE:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if MARK_EXPECT not in text and MARK_ALLOW not in text:
            continue
        relative = path.relative_to(root).as_posix()
        for number, line in enumerate(text.splitlines(), 1):
            for rule in _rules_after(line, MARK_EXPECT):
                expected.add((relative, number, rule))
            for rule in _rules_after(line, MARK_ALLOW):
                allowed.add((relative, number, rule))
    return expected, allowed


def _run(root: Path, cross_file: bool) -> Tuple[Set[Key], float, int]:
    started = time.perf_counter()
    result = scan(str(root), Config(cross_file_analysis=cross_file))
    elapsed = time.perf_counter() - started
    found = {(finding.path, finding.line, finding.rule_id) for finding in result.findings}
    return found, elapsed, result.stats.files_analyzed


def score_found(
    found: Set[Key],
    expected: Set[Key],
    allowed: Iterable[Key] = (),
    known_fp: Iterable[Key] = (),
    strict_unknown: bool = True,
) -> Score:
    allowed_set = set(allowed)
    known = set(known_fp)
    score = Score()
    hits = found & expected
    score.tp = len(hits)
    score.false_negatives = sorted(expected - found)
    score.fn = len(score.false_negatives)
    for key in sorted(found - expected):
        if key in allowed_set:
            score.neutral += 1
        elif key in known or strict_unknown:
            score.fp += 1
            score.false_positives.append(key)
        else:
            score.untriaged += 1
            score.false_positives.append(key)
    return score


def score_marked(root: Path, cross_file: bool = True) -> Score:
    expected, allowed = parse_markers(root)
    found, elapsed, files = _run(root, cross_file)
    score = score_found(found, expected, allowed)
    score.seconds = elapsed
    score.files = files
    return score


# ----------------------------------------------------------- tiers 1-3
def marked_cases(tier: int) -> List[Path]:
    base = CORPUS / ("tier%d" % tier)
    if not base.is_dir():
        return []
    return sorted(path for path in base.iterdir() if path.is_dir())


def run_marked_tier(tier: int, compare: bool = True) -> Dict[str, object]:
    total = Score()
    total_off = Score()
    cases = []
    for case in marked_cases(tier):
        score = score_marked(case, cross_file=True)
        total.add(score)
        entry: Dict[str, object] = {"case": case.name, "with_cross_file": score.as_dict()}
        if compare:
            off = score_marked(case, cross_file=False)
            total_off.add(off)
            entry["without_cross_file"] = off.as_dict()
        cases.append(entry)
    report: Dict[str, object] = {"tier": tier, "cases": cases, "total": total.as_dict()}
    if compare:
        report["total_without_cross_file"] = total_off.as_dict()
    return report


# ------------------------------------------------------------- output
def _line(name: str, score: Dict[str, object]) -> str:
    return "  %-26s TP=%-4s FP=%-4s FN=%-4s P=%.3f R=%.3f F1=%.3f  %5.1fs" % (
        name,
        score["tp"],
        score["fp"] + score.get("untriaged", 0),  # type: ignore[operator]
        score["fn"],
        score["precision"],
        score["recall"],
        score["f1"],
        score["seconds"],
    )


def print_report(reports: List[Dict[str, object]]) -> None:
    for report in reports:
        print("Tầng %s" % report["tier"])
        for case in report["cases"]:  # type: ignore[union-attr]
            print(_line(str(case["case"]), case["with_cross_file"]))
        print(_line("TỔNG", report["total"]))  # type: ignore[arg-type]
        if "total_without_cross_file" in report:
            print(_line("TỔNG ( tắt xuyên file )", report["total_without_cross_file"]))  # type: ignore[arg-type]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--tier", type=int, action="append", choices=(1, 2, 3), help="chỉ chạy tầng này ( lặp được )")
    parser.add_argument("--no-compare", action="store_true", help="không chạy lại với phân tích xuyên file bị tắt")
    parser.add_argument("--json", help="ghi kết quả đầy đủ ra tệp JSON")
    parser.add_argument("--show-misses", action="store_true", help="in từng FP/FN của tầng 1-3")
    args = parser.parse_args(argv)
    tiers = args.tier or [1, 2, 3]
    compare = not args.no_compare
    reports = [run_marked_tier(tier, compare) for tier in tiers]
    print_report(reports)
    if args.show_misses:
        for report in reports:
            total = report["total"]
            for item in total["false_positives"]:  # type: ignore[index]
                print("FP %s" % item)
            for item in total["false_negatives"]:  # type: ignore[index]
                print("FN %s" % item)
    if args.json:
        Path(args.json).write_text(json.dumps(reports, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
