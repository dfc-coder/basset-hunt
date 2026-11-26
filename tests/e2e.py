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
        nested_findings = scan("git-range", str(nested_dir), "--base", base, "--head", key_commit, code=1)
        assert any(r["location"]["path"] == key_path.name for r in nested_findings)

        pathspec_base = key_commit
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
