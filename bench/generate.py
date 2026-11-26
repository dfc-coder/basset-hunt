#!/usr/bin/env python3
"""Generate a seeded synthetic secret corpus and its labels.

Every value is random and non-functional. Detectable formats are assembled from
fragments so this source file contains no detectable secret.
"""
import argparse
import json
import random
import string
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


def generate(out, seed, per_family):
    rng = random.Random(seed)
    (out / "files").mkdir(parents=True)
    cases = []
    for provider, family, make in POSITIVES:
        for n in range(per_family):
            case = write_case(out, rng, f"pos-{provider}-{n}", f"{provider.upper()}_SECRET", make(rng), family == "private-key")
            cases.append(case | {"secret": True, "family": family, "provider": provider, "encoding": "plain"})
    for n, (kind, make) in enumerate(NEGATIVES):
        case = write_case(out, rng, f"neg-{kind}-{n}", "REFERENCE", make(rng), False)
        cases.append(case | {"secret": False, "family": "negative", "kind": kind, "encoding": "plain"})
    labels = {"version": 1, "seed": seed, "cases": cases}
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
