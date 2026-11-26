#!/usr/bin/env python3
"""Generate a seeded synthetic secret corpus and its labels.

Every value is random and non-functional. Detectable formats are assembled from
fragments so this source file contains no detectable secret.
"""
import argparse
import base64
import gzip
import io
import json
import os
import random
import string
import subprocess
import tarfile
import zipfile
from pathlib import Path

ALNUM = string.ascii_letters + string.digits
LOWER = string.ascii_lowercase + string.digits
HEX = "0123456789abcdef"
B32 = string.ascii_uppercase + "234567"
DASH = "-" * 5
SEP = ":" + "//"


def pick(rng, alphabet, n):
    return "".join(rng.choice(alphabet) for _ in range(n))


def private_key(rng):
    body = "\n".join(pick(rng, ALNUM + "+/", 64) for _ in range(12))
    return f"{DASH}BEGIN RSA PRIVATE KEY{DASH}\n{body}\n{DASH}END RSA PRIVATE KEY{DASH}"


# (provider, family, generator)
POSITIVES = [
    ("github", "token", lambda r: "gh" + "p_" + pick(r, ALNUM, 36)),
    ("gitlab", "token", lambda r: "gl" + "pat-" + pick(r, ALNUM, 20)),
    ("slack", "token", lambda r: f"xo" f"xb-{pick(r, string.digits, 12)}-{pick(r, string.digits, 13)}-{pick(r, ALNUM, 24)}"),
    ("npm", "token", lambda r: "np" + "m_" + pick(r, LOWER, 36)),
    ("aws", "api-key", lambda r: "AK" + "IA" + pick(r, B32, 16)),
    ("stripe", "api-key", lambda r: "sk_" + "live_" + pick(r, ALNUM, 24)),
    ("google", "api-key", lambda r: "AI" + "za" + pick(r, ALNUM + "-_", 35)),
    ("openai", "api-key", lambda r: "sk-" + "proj-" + pick(r, ALNUM, 48) + "T3Blbk" + "FJ" + pick(r, ALNUM, 48)),
    ("anthropic", "api-key", lambda r: "sk-ant-" + "api03-" + pick(r, ALNUM, 93) + "AA"),
    ("azure", "api-key", lambda r: pick(r, ALNUM, 3) + r.choice(string.digits) + "Q" + "~" + pick(r, ALNUM, 32)),
    ("sendgrid", "api-key", lambda r: "S" + "G." + pick(r, ALNUM, 22) + "." + pick(r, ALNUM, 43)),
    ("postgres", "db-connection", lambda r: f"postgres{SEP}app:{pick(r, ALNUM, 20)}@db.internal:5432/app"),
    ("mysql", "db-connection", lambda r: f"mysql{SEP}app:{pick(r, ALNUM, 20)}@db.internal:3306/app"),
    ("rsa", "private-key", private_key),
]

GENERATORS = {provider: (family, make) for provider, family, make in POSITIVES}
ISSUED = []  # every secret value written, for the leak check

# (kind, generator) -- realistic values that are not secrets
NEGATIVES = [
    ("documentation-example", lambda r: "AK" + "IAIOSFODNN7EXAMPLE"),
    ("commit-hash", lambda r: pick(r, HEX, 40)),
    ("sha256", lambda r: pick(r, HEX, 64)),
    ("uuid", lambda r: "-".join(pick(r, HEX, n) for n in (8, 4, 4, 4, 12))),
    ("placeholder", lambda r: "gh" + "p_" + "x" * 36),
    ("placeholder", lambda r: "your-api-key-here"),
    ("placeholder", lambda r: "sk_" + "live_" + "0" * 24),
    ("public-identifier", lambda r: "pk_" + "live_" + pick(r, ALNUM, 24)),
    ("public-identifier", lambda r: f"{pick(r, string.digits, 12)}-{pick(r, LOWER, 32)}.apps.googleusercontent.com"),
]

CONTEXTS = [
    ("env", lambda k, v: f"{k}={v}"),
    ("yaml", lambda k, v: f'{k.lower()}: "{v}"'),
    ("py", lambda k, v: f'{k} = "{v}"'),
    ("json", lambda k, v: f'{{"{k.lower()}": "{v}"}}'),
]
FILLER = ["LOG_LEVEL=info", "REGION=eu-west-1", "TIMEOUT=30", "FEATURE_FLAGS=search,export", "REPLICAS=3"]


def write_case(out, rng, case_id, key, value, multiline):
    filler = rng.sample(FILLER, rng.randint(0, len(FILLER)))
    if multiline:
        ext, line = "pem", value
    else:
        ext, render = rng.choice(CONTEXTS)
        line = render(key, value)
    path = Path("files") / f"{case_id}.{ext}"
    (out / path).write_text("\n".join(filler + [line]) + "\n")
    return {"id": case_id, "path": path.as_posix(), "line": len(filler) + 1}


GIT_ENV = {
    "GIT_AUTHOR_NAME": "Bench", "GIT_AUTHOR_EMAIL": "bench@example.invalid",
    "GIT_COMMITTER_NAME": "Bench", "GIT_COMMITTER_EMAIL": "bench@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
}


def make(provider, rng):
    value = GENERATORS[provider][1](rng)
    ISSUED.append(value)
    return value


def secret_case(case_id, provider, **fields):
    base = {"id": case_id, "secret": True, "family": GENERATORS[provider][0], "provider": provider}
    return base | {"source": "files", "encoding": "plain"} | fields


def encoded(out, rng):
    (out / "encoded").mkdir()
    chains = [
        ("github", "base64", lambda v: base64.b64encode(v.encode()).decode()),
        ("gitlab", "hex", lambda v: v.encode().hex()),
        ("stripe", "base64>hex", lambda v: base64.b64encode(v.encode().hex().encode()).decode()),
    ]
    cases = []
    for provider, chain, encode in chains:
        path = f"encoded/{provider}.txt"
        (out / path).write_text(f"# encoded payload\npayload: {encode(make(provider, rng))}\n")
        cases.append(secret_case(f"enc-{provider}", provider, path=path, line=2, encoding=chain))
    return cases


def archives(out, rng):
    (out / "archives").mkdir()
    zip_entry, tar_entry = "config/app.env", "etc/service/app.env"
    with zipfile.ZipFile(out / "archives/bundle.zip", "w") as z:
        z.writestr(zipfile.ZipInfo(zip_entry, date_time=(2026, 1, 1, 0, 0, 0)),
                   f"LOG_LEVEL=info\nSLACK_TOKEN={make('slack', rng)}\n" + "FEATURE_FLAGS=search,export\n" * 40,
                   compress_type=zipfile.ZIP_DEFLATED)
    data = f"REGION=eu-west-1\nAWS_KEY={make('aws', rng)}\n".encode()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo(tar_entry)
        info.size, info.mtime = len(data), 0
        tar.addfile(info, io.BytesIO(data))
    (out / "archives/layer.tar.gz").write_bytes(gzip.compress(raw.getvalue(), mtime=0))
    return [
        secret_case("arc-zip", "slack", path="archives/bundle.zip", archive="zip", entry=zip_entry, line=2),
        secret_case("arc-tar", "aws", path="archives/layer.tar.gz", archive="tar.gz", entry=tar_entry, line=2),
    ]


def repo(out, rng):
    root = out / "repo"
    root.mkdir()

    def git(*args, check=True):
        result = subprocess.run(["git", "-C", str(root), *args], env=os.environ | GIT_ENV,
                                text=True, capture_output=True, check=check)
        return result.stdout.strip()

    def commit(files, message):
        for name, text in files.items():
            (root / name).write_text(text)
            git("add", name)
        git("commit", "-q", "-m", message)
        return git("rev-parse", "HEAD")

    git("init", "-q", "-b", "main")
    commit({"config.env": "MODE=base\n"}, "initial config")
    in_file = commit({"deploy.env": f"REGION=eu-west-1\nGITHUB_TOKEN={make('github', rng)}\n"}, "add deploy settings")
    in_message = commit({"README.md": "service\n"}, f"rotate credentials\n\nslack: {make('slack', rng)}")
    git("notes", "add", "-m", f"temporary npm token {make('npm', rng)}", in_message)
    git("switch", "-q", "-c", "feature")
    in_branch = commit({"config.env": "MODE=feature\n", "feature.env": f"STRIPE_KEY={make('stripe', rng)}\n"}, "feature config")
    git("switch", "-q", "main")
    commit({"config.env": "MODE=main\n"}, "main config")
    git("merge", "-q", "--no-edit", "feature", check=False)  # conflicts on config.env by design
    in_merge = commit({"config.env": f"MODE=main\nGITLAB_TOKEN={make('gitlab', rng)}\n"}, "merge feature")
    git_case = lambda case_id, provider, commit_id, field, path, line: secret_case(
        case_id, provider, source="git", commit=commit_id, field=field, path=path, line=line)
    return [
        git_case("git-file", "github", in_file, "file", "deploy.env", 2),
        git_case("git-message", "slack", in_message, "message", None, 3),
        git_case("git-notes", "npm", in_message, "notes", None, 1),
        git_case("git-branch", "stripe", in_branch, "file", "feature.env", 1),
        git_case("git-merge-resolution", "gitlab", in_merge, "file", "config.env", 2) | {"scenario": "merge-resolution"},
    ]


def generate(out, seed, per_family):
    rng = random.Random(seed)
    (out / "files").mkdir(parents=True)
    cases = []
    ISSUED.clear()
    for provider, family, _ in POSITIVES:
        for n in range(per_family):
            case = write_case(out, rng, f"pos-{provider}-{n}", f"{provider.upper()}_SECRET", make(provider, rng), family == "private-key")
            cases.append(case | {"secret": True, "family": family, "provider": provider, "source": "files", "encoding": "plain"})
    for n, (kind, negative) in enumerate(NEGATIVES):
        case = write_case(out, rng, f"neg-{kind}-{n}", "REFERENCE", negative(rng), False)
        cases.append(case | {"secret": False, "family": "negative", "kind": kind, "source": "files", "encoding": "plain"})
    cases += encoded(out, rng) + archives(out, rng) + repo(out, rng)
    labels = {"version": 1, "seed": seed, "cases": cases, "secret_values": ISSUED}
    (out / "labels.json").write_text(json.dumps(labels, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path, help="output directory; must not exist")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--per-family", type=int, default=3)
    args = parser.parse_args()
    if args.out.exists():
        parser.error(f"{args.out} already exists")
    generate(args.out, args.seed, args.per_family)


if __name__ == "__main__":
    main()
