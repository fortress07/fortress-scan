#!/usr/bin/env python3
"""Đo độ chính xác của fortress-scan trên corpus bốn tầng, bằng một lệnh.

    python tools/benchmark.py                 # tầng 1-3 ( có sẵn trong repo ) + tầng 4 nếu đã tải
    python tools/benchmark.py --tier 4        # chỉ các repo thật trong .corpus-cache/
    python tools/benchmark.py --json out.json --markdown out.md

Tầng 1-3 nằm trong tests/corpus và chạy hoàn toàn offline. Kỳ vọng được ghi
ngay trên dòng có lỗi:

    db.query("... " + req.query.name)   // fsb-expect: FSB-SQL-001

Dòng không có `fsb-expect` mà vẫn bị báo là dương tính giả. `fsb-allow: RULE`
đánh dấu một gợi ý kiểm tra hợp lệ trên dòng an toàn ( ví dụ FSB-SQL-002 cho
câu SQL dựng động từ hằng ): nó không tính là đúng mà cũng không tính là sai.

Tầng 4 là repo mã nguồn mở thật, ghim theo commit trong
tests/corpus/tier4/repos.json và tải bằng tools/fetch_corpus.py ( chỉ lúc
chuẩn bị, công cụ quét không bao giờ tự lên mạng ). Kỳ vọng của tầng 4 là
danh sách đã phân loại tay: lỗi thật cần tìm ( `expected` ), cảnh báo đã xác
nhận là sai ( `false_positives` ); cảnh báo mới chưa ai phân loại được đếm
riêng là `untriaged` và tính như dương tính giả khi tính precision.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
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
CACHE = Path(os.environ.get("FSB_CORPUS_CACHE", str(ROOT / ".corpus-cache")))
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


# --------------------------------------------------------------- tier 4
def load_repos() -> List[Dict[str, object]]:
    manifest = CORPUS / "tier4" / "repos.json"
    if not manifest.is_file():
        return []
    return json.loads(manifest.read_text(encoding="utf-8"))["repos"]


def _key(entry: Dict[str, object]) -> Key:
    return (str(entry["path"]), int(entry["line"]), str(entry.get("rule") or "?"))


def run_triaged(repo: Dict[str, object], checkout: Path, compare: bool) -> Dict[str, object]:
    scope = checkout / str(repo.get("scope", "."))
    expected = {_key(item) for item in repo.get("expected", [])}
    known_fp = {_key(item) for item in repo.get("false_positives", [])}
    report: Dict[str, object] = {"name": repo["name"], "kind": "triaged", "commit": repo["commit"]}
    modes = [(True, "with_cross_file")] + ([(False, "without_cross_file")] if compare else [])
    for cross_file, label in modes:
        found, elapsed, files = _run(scope, cross_file)
        score = score_found(found, expected, known_fp=known_fp, strict_unknown=False)
        score.seconds = elapsed
        score.files = files
        report[label] = score.as_dict()
    return report


_BENCHMARK_CWE = {
    "cmdi": "CWE-78",
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "pathtraver": "CWE-22",
    "ldapi": "CWE-90",
    "xpathi": "CWE-643",
    "crypto": "CWE-327",
    "hash": "CWE-328",
    "weakrand": "CWE-330",
    "securecookie": "CWE-614",
    "trustbound": "CWE-501",
}


def run_owasp_benchmark(repo: Dict[str, object], checkout: Path, compare: bool) -> Dict[str, object]:
    """Chấm theo đúng luật của OWASP Benchmark: từng test case, theo CWE.

    Một test case được coi là "bị báo" khi có ít nhất một phát hiện mang đúng
    CWE của hạng mục nằm trong tệp của test case đó. Gợi ý kiểm tra cấp thấp
    ( *-002/*-003 ) không tính, vì chúng không khẳng định có lỗi.
    """
    expected: Dict[str, Tuple[str, bool]] = {}
    with open(checkout / str(repo["expected_csv"]), encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if not row or row[0].startswith("#"):
                continue
            expected[row[0].strip()] = (row[1].strip(), row[2].strip() == "true")
    hint_rules = set(repo.get("hint_rules", []))
    report: Dict[str, object] = {"name": repo["name"], "kind": "owasp-benchmark", "commit": repo["commit"]}
    modes = [(True, "with_cross_file")] + ([(False, "without_cross_file")] if compare else [])
    for cross_file, label in modes:
        started = time.perf_counter()
        result = scan(str(checkout / str(repo.get("scope", "."))), Config(cross_file_analysis=cross_file))
        elapsed = time.perf_counter() - started
        flagged: Dict[str, Set[str]] = {}
        for finding in result.findings:
            if finding.rule_id in hint_rules:
                continue
            name = finding.path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
            if name in expected:
                flagged.setdefault(name, set()).update(finding.cwe)
        categories: Dict[str, Dict[str, object]] = {}
        for name, (category, real) in expected.items():
            row = categories.setdefault(category, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
            hit = _BENCHMARK_CWE.get(category, "") in flagged.get(name, set())
            row[("tp" if hit else "fn") if real else ("fp" if hit else "tn")] += 1  # type: ignore[operator]
        for row in categories.values():
            positives = row["tp"] + row["fn"]  # type: ignore[operator]
            negatives = row["fp"] + row["tn"]  # type: ignore[operator]
            row["tpr"] = round(row["tp"] / positives, 4) if positives else 0.0  # type: ignore[operator]
            row["fpr"] = round(row["fp"] / negatives, 4) if negatives else 0.0  # type: ignore[operator]
            row["score"] = round(row["tpr"] - row["fpr"], 4)  # type: ignore[operator]
        report[label] = {"seconds": round(elapsed, 2), "files": result.stats.files_analyzed, "categories": categories}
    return report


def run_tier4(compare: bool = True, names: Optional[Sequence[str]] = None) -> Dict[str, object]:
    repos = []
    missing = []
    for repo in load_repos():
        if names and repo["name"] not in names:
            continue
        checkout = CACHE / str(repo["name"])
        if not (checkout / ".fsb-commit").is_file():
            missing.append(repo["name"])
            continue
        pinned = (checkout / ".fsb-commit").read_text(encoding="utf-8").strip()
        if pinned != repo["commit"]:
            missing.append("%s ( đang ở %s, cần %s )" % (repo["name"], pinned[:12], str(repo["commit"])[:12]))
            continue
        if repo.get("kind") == "owasp-benchmark":
            repos.append(run_owasp_benchmark(repo, checkout, compare))
        else:
            repos.append(run_triaged(repo, checkout, compare))
    return {"tier": 4, "repos": repos, "missing": missing}


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
        tier = report["tier"]
        if tier != 4:
            print("Tầng %s" % tier)
            for case in report["cases"]:  # type: ignore[union-attr]
                print(_line(str(case["case"]), case["with_cross_file"]))
            print(_line("TỔNG", report["total"]))  # type: ignore[arg-type]
            if "total_without_cross_file" in report:
                print(_line("TỔNG ( tắt xuyên file )", report["total_without_cross_file"]))  # type: ignore[arg-type]
            continue
        print("Tầng 4")
        for repo in report["repos"]:  # type: ignore[union-attr]
            if repo["kind"] == "owasp-benchmark":
                for label in ("with_cross_file", "without_cross_file"):
                    if label not in repo:
                        continue
                    print("  %s ( %s, %ss )" % (repo["name"], label, repo[label]["seconds"]))
                    for category, row in sorted(repo[label]["categories"].items()):
                        print(
                            "    %-12s TP=%-4s FP=%-4s FN=%-4s TN=%-4s TPR=%.2f FPR=%.2f score=%+.2f"
                            % (category, row["tp"], row["fp"], row["fn"], row["tn"], row["tpr"], row["fpr"], row["score"])
                        )
                continue
            print(_line(str(repo["name"]), repo["with_cross_file"]))
            if "without_cross_file" in repo:
                print(_line("  ( tắt xuyên file )", repo["without_cross_file"]))
        for name in report.get("missing", []):  # type: ignore[union-attr]
            print("  bỏ qua %s: chưa tải, chạy tools/fetch_corpus.py" % name)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--tier", type=int, action="append", choices=(1, 2, 3, 4), help="chỉ chạy tầng này ( lặp được )")
    parser.add_argument("--repo", action="append", help="tầng 4: chỉ chạy repo này")
    parser.add_argument("--no-compare", action="store_true", help="không chạy lại với phân tích xuyên file bị tắt")
    parser.add_argument("--json", help="ghi kết quả đầy đủ ra tệp JSON")
    parser.add_argument("--show-misses", action="store_true", help="in từng FP/FN của tầng 1-3")
    args = parser.parse_args(argv)
    tiers = args.tier or [1, 2, 3, 4]
    compare = not args.no_compare
    reports: List[Dict[str, object]] = []
    for tier in tiers:
        if tier == 4:
            reports.append(run_tier4(compare, args.repo))
        else:
            reports.append(run_marked_tier(tier, compare))
    print_report(reports)
    if args.show_misses:
        for report in reports:
            if report["tier"] == 4:
                continue
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
