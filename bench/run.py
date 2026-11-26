#!/usr/bin/env python3
"""Run Basset, Gitleaks and TruffleHog on the same synthetic corpus and score them."""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

PINNED = {"gitleaks": "8.30.1", "trufflehog": "3.100.1"}
CATEGORIES = ["plain", "encoded", "archive", "git-file", "git-message", "git-notes", "merge-resolution"]


def category(case):
    if case["source"] == "files":
        return "archive" if "archive" in case else "plain" if case["encoding"] == "plain" else "encoded"
    if case.get("scenario") == "merge-resolution":
        return "merge-resolution"
    return f"git-{case['field']}"


def measure(argv, cwd, out_file):
    """Run argv, capturing stdout to out_file; return (exit code, seconds, peak RSS in KB)."""
    start = time.monotonic()
    with open(out_file, "wb") as out:
        proc = subprocess.Popen(argv, cwd=cwd, stdout=out, stderr=subprocess.DEVNULL)
        _, status, usage = os.wait4(proc.pid, 0)
    return os.waitstatus_to_exitcode(status), time.monotonic() - start, usage.ru_maxrss


def hit(path, line, commit=None):
    return {"path": os.path.normpath(path) if path else None, "line": line, "commit": commit}


def parse(tool, mode, raw):
    if tool == "gitleaks":
        return [hit(f["File"], f["StartLine"], f["Commit"] or None) for f in json.loads(raw or "[]")]
    hits = []
    for line in raw.splitlines():
        rec = json.loads(line)
        if tool == "basset" and "location" in rec:
            hits.append(hit(rec["location"]["path"], rec["line"], rec["location"]["revision"]))
        elif tool == "trufflehog":
            meta = rec["SourceMetadata"]["Data"]["Git" if mode == "git" else "Filesystem"]
            hits.append(hit(meta.get("file"), meta.get("line"), meta.get("commit")))
    return hits


def matches(case, mode, h):
    if (case["source"] == "git") != (mode == "git"):
        return False
    if "archive" in case:
        return (h["path"] or "").split("!")[0] == case["path"]
    field = case.get("field", "file")
    if field == "file":
        return h["path"] == case["path"] and h["line"] == case["line"]
    if field == "message":
        return h["commit"] == case["commit"] and h["path"] in (None, f"{case['commit']}:message")
    return h["path"] in (case["commit"], f"{case['commit']}:notes")


def commands(tool, binary, mode, target, report):
    if tool == "basset":
        return [binary, "fs" if mode == "fs" else "git", target], None
    if tool == "gitleaks":
        sub = "dir" if mode == "fs" else "git"
        return [binary, sub, target, "--no-banner", "--redact", "--max-archive-depth", "3",
                "-f", "json", "-r", str(report), "--exit-code", "0"], report
    sub, src = ("filesystem", target) if mode == "fs" else ("git", f"file://{Path(target).resolve()}")
    return [binary, sub, src, "--json", "--no-verification", "--no-update"], None


def check_version(tool, binary):
    argv = [binary, "version"] if tool == "gitleaks" else [binary, "--version"]
    try:
        text = subprocess.run(argv, capture_output=True, text=True).stdout
    except OSError:
        sys.exit(f"{tool} not found: {binary}")
    version = text.strip().split()[-1] if text.strip() else ""
    if tool in PINNED and version != PINNED[tool]:
        sys.exit(f"{tool} {PINNED[tool]} required, found {version or 'nothing'}")
    return version


def score(cases, hits):
    detected = {c["id"] for c in cases if c["secret"] and any(matches(c, m, h) for m, h in hits)}
    fp = [h for m, h in hits if not any(c["secret"] and matches(c, m, h) for c in cases)]
    positives = [c for c in cases if c["secret"]]

    def group(key):
        rows = {}
        for c in positives:
            row = rows.setdefault(key(c), {"tp": 0, "misses": 0, "missed": []})
            if c["id"] in detected:
                row["tp"] += 1
            else:
                row["misses"] += 1
                row["missed"].append(c["id"])
        for row in rows.values():
            row["recall"] = round(row["tp"] / (row["tp"] + row["misses"]), 4)
        return rows

    tp = len(detected)
    return {"families": group(lambda c: c["family"]), "categories": group(category),
            "tp": tp, "fp": len(fp), "precision": round(tp / (tp + len(fp)), 4) if tp + len(fp) else 1.0,
            "recall": round(tp / len(positives), 4)}


def markdown(report):
    tools = list(report["tools"])
    lines = [f"Corpus seed {report['seed']}. Versions: " + ", ".join(f"{t} {report['tools'][t]['version']}" for t in tools), ""]
    for title, key in (("Recall by family", "families"), ("Recall by category", "categories")):
        names = sorted({n for t in tools for n in report["tools"][t][key]})
        lines += [f"## {title}", "", "| | " + " | ".join(tools) + " |", "|---" * (len(tools) + 1) + "|"]
        lines += [f"| {n} | " + " | ".join(str(report["tools"][t][key].get(n, {}).get("recall", "-")) for t in tools) + " |" for n in names]
        lines.append("")
    lines += ["## Overall", "", "| | precision | recall | false positives | time (s) | peak RSS (MB) |", "|---|---|---|---|---|---|"]
    for t in tools:
        r = report["tools"][t]
        lines.append(f"| {t} | {r['precision']} | {r['recall']} | {r['fp']} | {r['time_s']} | {round(r['max_rss_kb'] / 1024)} |")
    lines += ["", "## Missed cases", ""]
    lines += [f"- **{t}**: " + (", ".join(sorted(i for row in report["tools"][t]["families"].values() for i in row["missed"])) or "none") for t in tools]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path, help="output directory; must not exist")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--basset", default="target/release/basset")
    parser.add_argument("--gitleaks", default="gitleaks")
    parser.add_argument("--trufflehog", default="trufflehog")
    args = parser.parse_args()
    if args.out.exists():
        parser.error(f"{args.out} already exists")
    binaries = {t: str(Path(getattr(args, t)).resolve()) if os.sep in getattr(args, t) else getattr(args, t)
                for t in ("basset", "gitleaks", "trufflehog")}
    versions = {t: check_version(t, b) for t, b in binaries.items()}
    corpus = args.out / "corpus"
    subprocess.run([sys.executable, str(Path(__file__).with_name("generate.py")), str(corpus), "--seed", str(args.seed)], check=True)
    tree = args.out / "tree"
    for name in ("files", "encoded", "archives"):
        shutil.copytree(corpus / name, tree / name)
    cases = json.loads((corpus / "labels.json").read_text())["cases"]
    report = {"version": 1, "seed": args.seed, "tools": {}}
    for tool, binary in binaries.items():
        hits, seconds, rss = [], 0.0, 0
        for mode, cwd in (("fs", tree), ("git", corpus / "repo")):
            raw_file = args.out / f"{tool}-{mode}.out"
            target = "." if mode == "fs" else str(cwd.resolve())
            argv, report_file = commands(tool, binary, mode, target, args.out.resolve() / f"{tool}-{mode}.json")
            code, spent, peak = measure(argv, cwd, raw_file)
            if code not in ((0, 1) if tool == "basset" else (0,)):
                sys.exit(f"{tool} {mode} exited {code}")
            raw = Path(report_file).read_text() if report_file else raw_file.read_text()
            hits += [(mode, h) for h in parse(tool, mode, raw)]
            seconds, rss = seconds + spent, max(rss, peak)
        report["tools"][tool] = score(cases, hits) | {"version": versions[tool], "time_s": round(seconds, 3), "max_rss_kb": rss}
    (args.out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (args.out / "report.md").write_text(markdown(report))
    print(markdown(report))


if __name__ == "__main__":
    main()
