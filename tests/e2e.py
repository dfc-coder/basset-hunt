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
    print("CLI integration checks passed")


if __name__ == "__main__":
    main()
