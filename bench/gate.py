#!/usr/bin/env python3
"""Apply the v1.0 release thresholds to a benchmark report.

Exit 0 and write gate.json next to the report when every threshold holds;
otherwise exit 1 and name each failed threshold and family.
"""
import hashlib
import json
import sys
from pathlib import Path

RIVALS = ("gitleaks", "trufflehog")
MAX_TIME_RATIO = 2.0


def failures(report):
    tools = report["tools"]
    basset = tools["basset"]
    found = []
    families = sorted({f for t in tools.values() for f in t["families"]})
    for family in families:
        ours = basset["families"].get(family, {}).get("recall", 0.0)
        best = max(tools[r]["families"].get(family, {}).get("recall", 0.0) for r in RIVALS)
        if ours < best:
            found.append(f"recall[{family}]: basset {ours} < best rival {best}")
    if basset["precision"] < tools["gitleaks"]["precision"]:
        found.append(f"precision: basset {basset['precision']} < gitleaks {tools['gitleaks']['precision']}")
    limit = MAX_TIME_RATIO * tools["gitleaks"]["time_s"]
    if basset["time_s"] > limit:
        found.append(f"time: basset {basset['time_s']}s > {MAX_TIME_RATIO}x gitleaks ({round(limit, 3)}s)")
    if basset["leaked_values"]:
        found.append(f"leak: {basset['leaked_values']} secret values in basset output")
    return found


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gate.py REPORT.json")
    path = Path(sys.argv[1])
    data = path.read_bytes()
    found = failures(json.loads(data))
    result = {"passed": not found, "failures": found, "report_sha256": hashlib.sha256(data).hexdigest()}
    if found:
        print("gate failed:\n" + "\n".join(f"  - {f}" for f in found))
        sys.exit(1)
    path.with_name("gate.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"gate passed (report sha256 {result['report_sha256']})")


if __name__ == "__main__":
    main()
