#!/usr/bin/env python
"""Scan dataset files with a scanner profile and compare against gold finding lines.

    python scripts/drift_check.py --profile latest --data tests/data/test.jsonl
    python scripts/drift_check.py --profile latest --data ../repo/dataset/train.jsonl \
        --map-out cloudsec/data/trivy_id_map.json

Findings are matched in stages, strictest first:
  exact           all fields identical
  id_or_severity  same tool, title and lines; id and/or severity differ
  same_check      same tool and check number (AVD-AWS-0089 == AWS-0089); title or lines differ
Anything left is missing (gold only) or new (scan only).
"""

import argparse
import json
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from cloudsec.builder import parse_input

ROOT = Path(__file__).resolve().parent.parent
FILENAME = {"TF": "main.tf", "CFN": "template.yaml", "K8S": "manifest.yaml", "IAM": "policy.json"}
NUMBERED = re.compile(r"^([A-Z]+)-?0*(\d+)$")
STAGES = [
    ("exact", lambda r: r),
    ("id_or_severity", lambda r: (r[0], r[3], r[4], r[5])),
    ("same_check", lambda r: (r[0], check_key(r[1]))),
]


def check_key(check_id: str) -> str:
    """Version-independent check identity: AVD-AWS-0089, AWS-0089 -> AWS-89; KSV001 -> KSV-1."""
    u = check_id.upper()
    if u.startswith("AVD-"):
        u = u[4:]
    m = NUMBERED.match(u)
    return f"{m[1]}-{int(m[2])}" if m else u


def filename_for(iac_type: str, content: str) -> str:
    name = FILENAME.get(iac_type, "file.yaml")
    if iac_type == "CFN" and content.lstrip().startswith("{"):
        name = "template.json"
    return name


from dataclasses import astuple

from cloudsec import scan as scanner


# Scanner calls live in cloudsec/scan.py; the drift check tests that code.
def run_checkov(bin_dir: Path, path: Path) -> list[tuple]:
    return [astuple(f) for f in scanner.run_checkov(bin_dir, path)]


def run_trivy(bin_dir: Path, folder: Path) -> list[tuple]:
    return [astuple(f) for f in scanner.run_trivy(bin_dir, folder)]


def match(gold: list[tuple], scan: list[tuple]):
    gold, scan = list(gold), list(scan)
    pairs = []
    for name, key in STAGES:
        pool = defaultdict(list)
        for j, s in enumerate(scan):
            if s is not None:
                pool[key(s)].append(j)
        for i, g in enumerate(gold):
            if g is None:
                continue
            js = pool.get(key(g))
            if js:
                j = js.pop(0)
                pairs.append((name, g, scan[j]))
                gold[i] = scan[j] = None
    return pairs, [g for g in gold if g], [s for s in scan if s]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", help="default: from scanners.toml")
    ap.add_argument("--data", default=str(ROOT / "tests/data/test.jsonl"))
    ap.add_argument("--report", help="JSON file for detailed differences")
    ap.add_argument("--map-out", help="write learned trivy id map (scanner id -> gold id)")
    args = ap.parse_args()
    args.profile = args.profile or scanner.default_profile()
    bin_dir = scanner.tools_dir(args.profile)
    report = args.report or f"/tmp/drift_{args.profile}_{Path(args.data).stem}.json"

    stats = {t: Counter() for t in ("checkov", "trivy")}
    id_pairs, details = Counter(), defaultdict(list)
    rows = [json.loads(line) for line in open(args.data, encoding="utf-8")]

    for i, r in enumerate(rows):
        file, findings = parse_input(r["input"])
        iac_type = r["output"].split("\n", 1)[0].split(":", 1)[1].strip()
        gold = [(f.tool, f.check_id, f.severity, f.title, f.start_line, f.end_line) for f in findings]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / filename_for(iac_type, file.content)
            path.write_text(file.content, encoding="utf-8")
            scan = run_checkov(bin_dir, path) + run_trivy(bin_dir, Path(tmp))

        pairs, missing, new = match(gold, scan)
        for stage, g, s in pairs:
            stats[g[0]][stage] += 1
            if stage != "exact":
                details[stage].append({"row": i, "gold": g, "scan": s})
            if stage in ("id_or_severity", "same_check") and g[1] != s[1]:
                id_pairs[(g[0], s[1], g[1])] += 1
        for g in missing:
            stats[g[0]]["missing"] += 1
            details["missing"].append({"row": i, "gold": g})
        for s in new:
            stats[s[0]]["new"] += 1
            details["new"].append({"row": i, "scan": s})
        print(f"  file {i + 1}/{len(rows)}", end="\r", flush=True)

    print()
    order = ["exact", "id_or_severity", "same_check", "missing", "new"]
    for tool, c in stats.items():
        gold_total = sum(c[k] for k in order if k != "new")
        print(f"{tool:8} gold {gold_total:5} | " + " | ".join(f"{k} {c[k]}" for k in order))

    for stage in ("same_check",):
        print(f"\n{stage} examples (gold -> scan):")
        for d in details[stage][:4]:
            g, s = d["gold"], d["scan"]
            print(f"  {g[1]} '{g[3]}' {g[4]}-{g[5]}  ->  {s[1]} '{s[3]}' {s[4]}-{s[5]}")
    print("\nmissing examples:", *[d["gold"] for d in details["missing"][:6]], sep="\n  ")

    Path(report).write_text(json.dumps(details, indent=1))
    print(f"\ndetails: {report}")

    targets = defaultdict(set)
    for (tool, new_id, old_id) in id_pairs:
        targets[(tool, new_id)].add(old_id)
    conflicts = {k: v for k, v in targets.items() if len(v) > 1}
    if conflicts:
        print("WARNING: scanner ids mapping to several gold ids:", conflicts)
    if args.map_out:
        m = {nid: next(iter(v)) for (t, nid), v in targets.items() if t == "trivy" and len(v) == 1}
        Path(args.map_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.map_out).write_text(json.dumps(dict(sorted(m.items())), indent=2) + "\n")
        print(f"wrote {len(m)} trivy id mappings to {args.map_out}")


if __name__ == "__main__":
    main()
