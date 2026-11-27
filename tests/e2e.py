"""Run against the compiled CLI. All credential-shaped values are synthetic."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import string
import subprocess
import sys
import tempfile
import time

BIN = Path(sys.argv[1]).resolve()
TOKEN = "gh" + "p_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
KEY = secrets.token_bytes(32)
ENV = {**os.environ, "BASSET_HMAC_KEY": KEY.hex()}


def scan(*args: str, data: str = "", code: int = 0) -> list[dict]:
    run = subprocess.run([BIN, *args], input=data, text=True, capture_output=True, env=ENV)
    assert TOKEN not in run.stdout + run.stderr, "source value exposed in output"
    assert run.returncode == code, (args, run.returncode, run.stderr)
    return [json.loads(line) for line in run.stdout.splitlines()]


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", repo, *args], text=True).strip()


def main() -> None:
    assert scan("rules")[0]["compiled_rules"] >= 800
    catalog = scan("rules", "--list")
    assert len({r["id"] for r in catalog}) >= 800
    scan("stdin", data="hello world")
    scan("stdin", "--only-verified", code=2)
    scan("stdin", "--max-bytes", "5", data="abcdef", code=2)
    scan("records", data='{"content":"' + TOKEN + '"}', code=2)
    digest = hmac.new(KEY, TOKEN.encode(), hashlib.sha256).hexdigest()
    fp = subprocess.check_output([BIN, "fingerprint"], input=TOKEN, text=True, env=ENV)
    assert fp.strip() == digest
    legacy_env = {**ENV, "CREDCHECK_HMAC_KEY": ENV["BASSET_HMAC_KEY"]}
    del legacy_env["BASSET_HMAC_KEY"]
    legacy_fp = subprocess.check_output([BIN, "fingerprint"], input=TOKEN, text=True, env=legacy_env)
    assert legacy_fp.strip() == digest
    sample = f"release\nGITHUB_TOKEN={TOKEN} # gitleaks:allow\n"
    scan("stdin", data=sample, code=1)
    scan("stdin", data=f"GITHUB_TOKEN={TOKEN} # secrets-scanner:allow\n", code=1)
    scan("stdin", data="ordinary comment # gitleaks:allow\n")
    candidates = scan("stdin", data=sample, code=1)
    assert any(r["line"] == 2 and r["fingerprint"] == digest and r["status"] == "unknown"
               for r in candidates)
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        inv = root / "inventory.json"
        check_time = int(time.time())
        row = dict(fingerprint=digest, state="active", checked_at=check_time,
                   owner="payments", permissions=["read"], rotation_runbook="rotate-payments")
        inv.write_text(json.dumps([row]))
        for flag in ("--only-verified", "--results=verified"):
            findings = scan("stdin", "--inventory", str(inv), flag, data=sample, code=1)
            assert all(r["status"] == "verified" and r["inventory"]["owner"] == "payments"
                       for r in findings)
        for change, status in [({"state": "revoked"}, "revoked"),
                               ({"checked_at": 1}, "stale"),
                               ({"checked_at": check_time + 3600}, "stale")]:
            inv.write_text(json.dumps([{**row, **change}]))
            scan("stdin", "--inventory", str(inv), "--only-verified", data=sample)
            findings = scan("stdin", "--inventory", str(inv), data=sample, code=1)
            assert any(r["status"] == status for r in findings)
        inv.write_text(json.dumps([row, row]))
        scan("stdin", "--inventory", str(inv), data=sample, code=2)
        item = dict(source="chat", path="day-1", content=sample, revision="1")
        records = scan("records", data=json.dumps(item) + "\n", code=1)
        assert records[0]["location"]["source"] == "chat"
        marked_file = root / "marked.env"
        marked_file.write_text(sample)
        scan("fs", str(marked_file), code=1)
        baseline = root / "baseline.json"
        scan("stdin", "--write-baseline", str(baseline), data=sample)
        baseline_text = baseline.read_text()
        baseline_data = json.loads(baseline_text)
        assert baseline_data["version"] == 1
        assert baseline_data["entries"]
        assert all(set(row) == {"rule", "location_fingerprint"}
                   for row in baseline_data["entries"])
        for row in baseline_data["entries"]:
            groups = row["location_fingerprint"].removeprefix("sha256:").split("-")
            assert len(groups) == 16 and all(len(group) == 4 for group in groups)
        scan("fs", str(baseline))
        assert TOKEN not in baseline_text
        assert hashlib.sha256(TOKEN.encode()).hexdigest() not in baseline_text
        assert digest not in baseline_text
        applied = subprocess.run(
            [BIN, "stdin", "--baseline", str(baseline)], input=sample,
            text=True, capture_output=True, env=ENV,
        )
        assert applied.returncode == 0 and not applied.stdout
        assert json.loads(applied.stderr.splitlines()[-1])["baselined"] > 0
        scan("stdin", "--name", "new.txt", "--baseline", str(baseline), data=sample, code=1)
        invalid_baseline = root / "invalid-baseline.json"
        invalid_baseline.write_text('{"version":1,"entries":[{"rule":"private-key"}]}')
        invalid = subprocess.run(
            [BIN, "stdin", "--baseline", str(invalid_baseline)], input=sample,
            text=True, capture_output=True, env=ENV,
        )
        assert invalid.returncode == 2 and not invalid.stdout
        assert "baseline" in invalid.stderr.lower()
        if os.name != "nt":
            protected = root / "protected.txt"
            protected.write_text("preserve this file")
            baseline_link = root / "baseline-link.json"
            baseline_link.symlink_to(protected)
            scan("stdin", "--write-baseline", str(baseline_link), data=sample)
            assert protected.read_text() == "preserve this file"
            assert not baseline_link.is_symlink()
            assert json.loads(baseline_link.read_text())["entries"]
        incomplete_baseline = root / "incomplete-baseline.json"
        scan("stdin", "--write-baseline", str(incomplete_baseline), "--max-bytes", "5",
             data="abcdef", code=2)
        assert not incomplete_baseline.exists()
        embedded_dir = root / "embedded-baseline"
        embedded_dir.mkdir()
        embedded_secret = embedded_dir / "secret.env"
        embedded_secret.write_text(sample)
        embedded_baseline = embedded_dir / "baseline.json"
        generated = subprocess.run(
            [BIN, "fs", str(embedded_secret), "--write-baseline", str(embedded_baseline)],
            text=True, capture_output=True, env=ENV,
        )
        assert generated.returncode == 0
        scan("fs", str(embedded_dir), code=1)
        scan("fs", str(embedded_secret), "--baseline", str(embedded_baseline))
        repo = root / "repo"
        repo.mkdir()
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "user.name", "Test")
        git(repo, "config", "user.email", "test@invalid.local")
        git(repo, "commit", "--allow-empty", "-qm", "root")
        git(repo, "switch", "-qc", "archived")
        path = repo / "spaced name.env"
        path.write_text(sample)
        git(repo, "add", "--", path.name)
        path.write_text("working copy clean\n")
        scan("fs", str(path))
        staged = scan("staged", str(repo), code=1)
        assert staged[0]["location"]["path"] == path.name
        git(repo, "commit", "-qm", "historical exposure")
        old = git(repo, "rev-parse", "HEAD")
        git(repo, "rm", "-qf", "--", path.name)
        git(repo, "commit", "-qm", "remove file")
        git(repo, "switch", "-q", "main")
        scan("staged", str(repo))
        history = scan("git", str(repo), code=1)
        assert any(r["location"]["revision"] == old and r["location"]["path"] == path.name
                   for r in history)
        range_repo = root / "range-repo"
        range_repo.mkdir()
        git(range_repo, "init", "-q", "-b", "main")
        git(range_repo, "config", "user.name", "Test")
        git(range_repo, "config", "user.email", "test@invalid.local")
        old_secret = range_repo / "old.env"
        old_secret.write_text(f"GITHUB_TOKEN={TOKEN}\n")
        private_key = subprocess.check_output(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
            stderr=subprocess.DEVNULL,
        ).decode()
        key_path = range_repo / "a[b].pem"
        incomplete_key = private_key.splitlines(keepends=True)
        assert len(incomplete_key) > 4
        incomplete_key[2] = "PLACEHOLDER\n"
        key_path.write_text("".join(incomplete_key))
        pathspec_decoy = range_repo / "ab.pem"
        pathspec_decoy.write_text("unchanged\n")
        nested_dir = range_repo / "nested"
        nested_dir.mkdir()
        nested_file = nested_dir / "nested.env"
        nested_file.write_text("before\n")
        nested_relative = nested_file.relative_to(range_repo).as_posix()
        git(range_repo, "add", "--", old_secret.name, key_path.name, pathspec_decoy.name, nested_relative)
        git(range_repo, "commit", "-qm", "base with prior secret")
        base = git(range_repo, "rev-parse", "HEAD")
        key_path.write_text(private_key)
        old_secret.write_text(old_secret.read_text() + "SAFE_CHANGE=true\n")
        nested_file.write_text(nested_file.read_text() + "changed\n")
        git(range_repo, "add", "--", old_secret.name, key_path.name, nested_relative)
        git(range_repo, "commit", "-qm", "add key and harmless line")
        key_commit = git(range_repo, "rev-parse", "HEAD")
        range_args = ["git-range", str(range_repo), "--base", base, "--head", key_commit]
        range_run = subprocess.run([BIN, *range_args], text=True, capture_output=True, env=ENV)
        assert TOKEN not in range_run.stdout + range_run.stderr
        assert private_key not in range_run.stdout + range_run.stderr
        assert range_run.returncode == 1, (range_run.returncode, range_run.stderr)
        range_findings = [json.loads(line) for line in range_run.stdout.splitlines()]
        assert range_findings and all(r["location"]["path"] == key_path.name for r in range_findings)
        assert any(r["detector"] == "private-key" and r["location"]["revision"] == key_commit
                   for r in range_findings)
        sarif_args = [*range_args, "--format", "sarif"]
        sarif_run = subprocess.run([BIN, *sarif_args], text=True, capture_output=True, env=ENV)
        assert sarif_run.returncode == 1, (sarif_run.returncode, sarif_run.stderr)
        sarif_text = sarif_run.stdout
        assert private_key not in sarif_text
        assert hashlib.sha256(private_key.encode()).hexdigest() not in sarif_text
        assert all(r["fingerprint"] not in sarif_text for r in range_findings)
        sarif_doc = json.loads(sarif_text)
        assert sarif_doc["version"] == "2.1.0"
        sarif_run_data = sarif_doc["runs"][0]
        assert sarif_run_data["invocations"][0]["executionSuccessful"] is True
        sarif_finding = sarif_run_data["results"][0]
        assert sarif_finding["ruleId"] == "private-key"
        assert sarif_finding["properties"]["commit"] == key_commit
        physical = sarif_finding["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == "a%5Bb%5D.pem"
        assert physical["region"]["startLine"] >= 1
        sarif_fingerprint = sarif_finding["partialFingerprints"]
        second_run = subprocess.run([BIN, *sarif_args], text=True, capture_output=True, env=ENV)
        assert second_run.returncode == 1
        second_sarif = json.loads(second_run.stdout)
        assert second_sarif["runs"][0]["results"][0]["partialFingerprints"] == sarif_fingerprint
        no_key_env = {key: value for key, value in ENV.items()
                      if key not in ("BASSET_HMAC_KEY", "CREDCHECK_HMAC_KEY")}
        no_key_run = subprocess.run([BIN, *sarif_args], text=True, capture_output=True, env=no_key_env)
        assert no_key_run.returncode == 1
        no_key_doc = json.loads(no_key_run.stdout)
        assert no_key_doc["runs"][0]["results"][0]["partialFingerprints"] == sarif_fingerprint

        unicode_secret = range_repo / "unicode.env"
        unicode_secret.write_text(f"é GITHUB_TOKEN={TOKEN} # gitleaks:allow\n")
        git(range_repo, "add", "--", unicode_secret.name)
        git(range_repo, "commit", "-qm", "add marked unicode secret")
        unicode_head = git(range_repo, "rev-parse", "HEAD")
        unicode_range = ["git-range", str(range_repo), "--base", key_commit,
                         "--head", unicode_head, "--format", "sarif"]
        unicode_run = subprocess.run([BIN, *unicode_range], text=True, capture_output=True, env=ENV)
        assert unicode_run.returncode == 1, (unicode_run.returncode, unicode_run.stderr)
        unicode_doc = json.loads(unicode_run.stdout)
        unicode_results = unicode_doc["runs"][0]["results"]
        token_result = next(result for result in unicode_results
                            if result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                            == unicode_secret.name)
        assert token_result["locations"][0]["physicalLocation"]["region"]["startColumn"] == 16
        marked_findings = scan("git-range", str(range_repo), "--base", key_commit,
                               "--head", unicode_head, code=1)
        assert any(r["location"]["path"] == unicode_secret.name for r in marked_findings)

        nested_findings = scan("git-range", str(nested_dir), "--base", base, "--head", key_commit, code=1)
        assert any(r["location"]["path"] == key_path.name for r in nested_findings)

        pathspec_base = unicode_head
        key_path.write_text(private_key + "SAFE_RANGE_CHANGE=true\n")
        pathspec_decoy.write_text("unchanged\ndecoy change\n")
        git(range_repo, "add", "--", key_path.name, pathspec_decoy.name)
        git(range_repo, "commit", "-qm", "change special paths harmlessly")
        pathspec_head = git(range_repo, "rev-parse", "HEAD")
        scan("git-range", str(range_repo), "--base", pathspec_base, "--head", pathspec_head)

        git(range_repo, "rm", "-qf", "--", key_path.name)
        git(range_repo, "commit", "-qm", "remove added key")
        removed = git(range_repo, "rev-parse", "HEAD")
        removed_findings = scan("git-range", str(range_repo), "--base", base, "--head", removed, code=1)
        assert any(r["location"]["revision"] == key_commit and r["location"]["path"] == key_path.name
                   for r in removed_findings)
        scan("git-range", str(range_repo), "--base", "not-a-commit", "--head", removed, code=2)
        scan("git-range", str(range_repo), "--base", base, "--head", base, code=2)
        invalid_sarif = subprocess.run(
            [BIN, "git-range", str(range_repo), "--base", "not-a-commit", "--head", removed, "--format", "sarif"],
            text=True, capture_output=True, env=ENV,
        )
        assert invalid_sarif.returncode == 2
        invalid_doc = json.loads(invalid_sarif.stdout)
        assert invalid_doc["runs"][0]["invocations"][0]["executionSuccessful"] is False
        invalid_inventory = subprocess.run(
            [BIN, *sarif_args, "--inventory", str(root / "missing-inventory.json")],
            text=True, capture_output=True, env=ENV,
        )
        assert invalid_inventory.returncode == 2
        inventory_doc = json.loads(invalid_inventory.stdout)
        assert inventory_doc["runs"][0]["invocations"][0]["executionSuccessful"] is False
        no_key_inventory = subprocess.run(
            [BIN, *sarif_args, "--inventory", str(root / "inventory.json")],
            text=True, capture_output=True, env=no_key_env,
        )
        assert no_key_inventory.returncode == 2
        no_key_doc = json.loads(no_key_inventory.stdout)
        assert no_key_doc["runs"][0]["invocations"][0]["executionSuccessful"] is False

        deletion_repo = root / "deletion-range-repo"
        deletion_repo.mkdir()
        git(deletion_repo, "init", "-q", "-b", "main")
        git(deletion_repo, "config", "user.name", "Test")
        git(deletion_repo, "config", "user.email", "test@invalid.local")
        deletion_file = deletion_repo / "delete.env"
        deletion_file.write_text(f"GITHUB_TOKEN={TOKEN}\nkeep=yes\n")
        git(deletion_repo, "add", "--", deletion_file.name)
        git(deletion_repo, "commit", "-qm", "base secret")
        deletion_base = git(deletion_repo, "rev-parse", "HEAD")
        deletion_file.write_text("keep=yes\n")
        git(deletion_repo, "add", "--", deletion_file.name)
        git(deletion_repo, "commit", "-qm", "delete old secret")
        deletion_head = git(deletion_repo, "rev-parse", "HEAD")
        scan("git-range", str(deletion_repo), "--base", deletion_base, "--head", deletion_head)
        empty_file = deletion_repo / "empty.txt"
        empty_file.touch()
        git(deletion_repo, "add", "--", empty_file.name)
        git(deletion_repo, "commit", "-qm", "add empty file")
        empty_head = git(deletion_repo, "rev-parse", "HEAD")
        scan("git-range", str(deletion_repo), "--base", deletion_head, "--head", empty_head)
        deletion_file.write_text("")
        git(deletion_repo, "add", "--", deletion_file.name)
        git(deletion_repo, "commit", "-qm", "truncate file")
        truncate_head = git(deletion_repo, "rev-parse", "HEAD")
        scan("git-range", str(deletion_repo), "--base", empty_head, "--head", truncate_head)

        binary = range_repo / "binary.dat"
        binary.write_bytes(b"\x00binary\xffdata")
        git(range_repo, "add", "--", binary.name)
        git(range_repo, "commit", "-qm", "add unsupported binary")
        binary_head = git(range_repo, "rev-parse", "HEAD")
        incomplete = subprocess.run(
            [BIN, "git-range", str(range_repo), "--base", base, "--head", binary_head],
            text=True, capture_output=True, env=ENV,
        )
        assert incomplete.returncode == 2, (incomplete.returncode, incomplete.stderr)
        assert private_key not in incomplete.stdout + incomplete.stderr
        partial = [json.loads(line) for line in incomplete.stdout.splitlines()]
        assert any(r["location"]["revision"] == key_commit for r in partial)
        partial_sarif = subprocess.run(
            [BIN, "git-range", str(range_repo), "--base", base, "--head", binary_head, "--format", "sarif"],
            text=True, capture_output=True, env=ENV,
        )
        assert partial_sarif.returncode == 2
        partial_doc = json.loads(partial_sarif.stdout)
        assert partial_doc["runs"][0]["invocations"][0]["executionSuccessful"] is False
        assert partial_doc["runs"][0]["results"]
        assert private_key not in partial_sarif.stdout

        cap_repo = root / "sarif-cap-repo"
        cap_repo.mkdir()
        git(cap_repo, "init", "-q", "-b", "main")
        git(cap_repo, "config", "user.name", "Test")
        git(cap_repo, "config", "user.email", "test@invalid.local")
        git(cap_repo, "commit", "--allow-empty", "-qm", "base")
        cap_base = git(cap_repo, "rev-parse", "HEAD")
        cap_tokens = ["ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
                      for _ in range(1001)]
        (cap_repo / "tokens.txt").write_text("".join(f"GITHUB_TOKEN={token}\n" for token in cap_tokens))
        git(cap_repo, "add", "--", "tokens.txt")
        git(cap_repo, "commit", "-qm", "many synthetic tokens")
        cap_head = git(cap_repo, "rev-parse", "HEAD")
        cap_sarif = subprocess.run(
            [BIN, "git-range", str(cap_repo), "--base", cap_base, "--head", cap_head, "--format", "sarif"],
            text=True, capture_output=True, env=ENV,
        )
        assert cap_sarif.returncode == 2
        assert all(token not in cap_sarif.stdout for token in cap_tokens)
        assert hashlib.sha256(cap_tokens[0].encode()).hexdigest() not in cap_sarif.stdout
        cap_doc = json.loads(cap_sarif.stdout)
        assert len(cap_doc["runs"][0]["results"]) == 1000
        assert cap_doc["runs"][0]["invocations"][0]["executionSuccessful"] is False

        scan("git-range", str(range_repo), "--base", base, "--head", binary_head, "--max-bytes", "64", code=2)

        shallow_repo = root / "shallow-range-repo"
        clone = subprocess.run(
            ["git", "clone", "--quiet", "--depth=2", range_repo.resolve().as_uri(), str(shallow_repo)],
            text=True, capture_output=True,
        )
        assert clone.returncode == 0, clone.stderr
        git(shallow_repo, "fetch", "-q", "--depth=1", "origin", base)
        assert git(shallow_repo, "rev-parse", "--is-shallow-repository") == "true"
        assert scan("git-range", str(shallow_repo), "--base", base, "--head", binary_head, code=2) == []
        shallow_sarif = subprocess.run(
            [BIN, "git-range", str(shallow_repo), "--base", base, "--head", binary_head, "--format", "sarif"],
            text=True, capture_output=True, env=ENV,
        )
        assert shallow_sarif.returncode == 2
        shallow_doc = json.loads(shallow_sarif.stdout)
        assert shallow_doc["runs"][0]["invocations"][0]["executionSuccessful"] is False

        root_repo = root / "root-range-repo"
        root_repo.mkdir()
        git(root_repo, "init", "-q", "-b", "main")
        git(root_repo, "config", "user.name", "Test")
        git(root_repo, "config", "user.email", "test@invalid.local")
        git(root_repo, "commit", "--allow-empty", "-qm", "base")
        root_base = git(root_repo, "rev-parse", "HEAD")
        git(root_repo, "switch", "-q", "--orphan", "root-only")
        root_key = root_repo / "root-key.pem"
        root_key.write_text(private_key)
        git(root_repo, "add", "--", root_key.name)
        git(root_repo, "commit", "-qm", "root commit with key")
        root_head = git(root_repo, "rev-parse", "HEAD")
        root_findings = scan("git-range", str(root_repo), "--base", root_base, "--head", root_head, code=1)
        assert any(r["location"]["revision"] == root_head and r["location"]["path"] == root_key.name
                   for r in root_findings)

        merge_repo = root / "merge-range-repo"
        merge_repo.mkdir()
        git(merge_repo, "init", "-q", "-b", "main")
        git(merge_repo, "config", "user.name", "Test")
        git(merge_repo, "config", "user.email", "test@invalid.local")
        git(merge_repo, "commit", "--allow-empty", "-qm", "base")
        merge_base = git(merge_repo, "rev-parse", "HEAD")
        git(merge_repo, "switch", "-qc", "side")
        branch_key = merge_repo / "branch-key.pem"
        branch_key.write_text(private_key)
        git(merge_repo, "add", "--", branch_key.name)
        git(merge_repo, "commit", "-qm", "add key on side branch")
        branch_commit = git(merge_repo, "rev-parse", "HEAD")
        git(merge_repo, "switch", "-q", "main")
        safe = merge_repo / "safe.txt"
        safe.write_text("harmless\n")
        git(merge_repo, "add", "--", safe.name)
        git(merge_repo, "commit", "-qm", "main line change")
        git(merge_repo, "merge", "--no-ff", "-qm", "merge side", "side")
        merge_head = git(merge_repo, "rev-parse", "HEAD")
        merge_findings = scan("git-range", str(merge_repo), "--base", merge_base, "--head", merge_head, code=1)
        assert any(r["location"]["revision"] == branch_commit and r["location"]["path"] == branch_key.name
                   for r in merge_findings)
        assert all(r["location"]["revision"] != merge_head for r in merge_findings)

        merge_gap_repo = root / "merge-gap-repo"
        merge_gap_repo.mkdir()
        git(merge_gap_repo, "init", "-q", "-b", "main")
        git(merge_gap_repo, "config", "user.name", "Test")
        git(merge_gap_repo, "config", "user.email", "test@invalid.local")
        conflict_file = merge_gap_repo / "conflict.txt"
        conflict_file.write_text("mode=common\n")
        git(merge_gap_repo, "add", "--", conflict_file.name)
        git(merge_gap_repo, "commit", "-qm", "common base")
        git(merge_gap_repo, "switch", "-qc", "topic")
        conflict_file.write_text("mode=topic\n")
        git(merge_gap_repo, "add", "--", conflict_file.name)
        git(merge_gap_repo, "commit", "-qm", "topic change")
        git(merge_gap_repo, "switch", "-q", "main")
        conflict_file.write_text("mode=main\n")
        inherited = merge_gap_repo / "inherited.env"
        inherited.write_text(f"GITHUB_TOKEN={TOKEN}\n")
        git(merge_gap_repo, "add", "--", conflict_file.name, inherited.name)
        git(merge_gap_repo, "commit", "-qm", "base update")
        merge_gap_base = git(merge_gap_repo, "rev-parse", "HEAD")
        git(merge_gap_repo, "switch", "-q", "topic")
        conflict = subprocess.run(
            ["git", "-C", str(merge_gap_repo), "merge", "--no-ff", "main"],
            text=True, capture_output=True,
        )
        assert conflict.returncode != 0
        conflict_file.write_text("mode=resolved\n" + private_key)
        git(merge_gap_repo, "add", "--", conflict_file.name)
        git(merge_gap_repo, "commit", "-qm", "resolve merge with key")
        merge_gap_head = git(merge_gap_repo, "rev-parse", "HEAD")
        assert scan("git-range", str(merge_gap_repo), "--base", merge_gap_base,
                    "--head", merge_gap_head) == []
    print("CLI integration checks passed")


if __name__ == "__main__":
    main()
