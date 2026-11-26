"""Refresh trusted inventory using an operator's AWS CLI profile and a provisioning manifest."""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


def aws(profile: str, *args: str) -> dict[str, Any]:
    result = subprocess.run(
        ["aws", "--profile", profile, "--output", "json", "--no-cli-pager", *args],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=90, check=False,
        env={k: v for k, v in os.environ.items() if k not in {"BASSET_HMAC_KEY", "CREDCHECK_HMAC_KEY"}},
    )
    if result.returncode:
        raise ValueError(f"AWS {args[0]} {args[1]} failed")
    return json.loads(result.stdout)


def refresh(manifest: dict[str, Any], profile: str) -> list[dict[str, Any]]:
    account = manifest["account"]
    if not re.fullmatch(r"[0-9]{12}", account) or aws(profile, "sts", "get-caller-identity")["Account"] != account:
        raise ValueError("operator profile does not match the provisioned AWS account")
    cache: dict[str, tuple[int, dict[str, str]]] = {}
    seen: set[str] = set()
    output = []
    states = {"Active": "active", "Inactive": "inactive", "Expired": "inactive"}
    for binding in manifest["keys"]:
        user, key_id, digest = (binding[k] for k in ("iam_user", "key_id", "fingerprint"))
        if not re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,64}", user) or user.startswith("-"):
            raise ValueError("invalid IAM user in manifest")
        if not re.fullmatch(r"[A-Za-z0-9]{16,128}", key_id):
            raise ValueError("invalid access key ID in manifest")
        if not re.fullmatch(r"[a-f0-9]{64}", digest) or digest in seen:
            raise ValueError("invalid or duplicate provisioning fingerprint")
        seen.add(digest)
        if user not in cache:
            checked_at = int(time.time())
            data = aws(profile, "iam", "list-access-keys", "--user-name", user)
            if data.get("IsTruncated") or data.get("NextToken"):
                raise ValueError("incomplete AWS response")
            keys = data["AccessKeyMetadata"]
            if any(k["UserName"] != user for k in keys):
                raise ValueError("IAM owner mismatch")
            cache[user] = checked_at, {k["AccessKeyId"]: states[k["Status"]] for k in keys}
        checked_at, by_id = cache[user]
        if key_id not in by_id:
            continue  # Missing binding has no trusted current status.
        owner = binding["owner"]
        runbook = binding.get("rotation_runbook")
        permissions = binding.get("permissions", [])
        if not isinstance(owner, str) or not owner.strip():
            raise ValueError("missing inventory owner")
        if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions):
            raise ValueError("invalid permissions")
        if runbook is not None and not isinstance(runbook, str):
            raise ValueError("invalid runbook")
        output.append(dict(fingerprint=digest, state=by_id[key_id], checked_at=checked_at,
                           owner=owner, permissions=permissions, rotation_runbook=runbook))
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--profile", required=True)
    args = parser.parse_args()
    pending: Path | None = None
    try:
        if args.manifest.resolve() == args.output.resolve():
            raise ValueError("output would overwrite provisioning manifest")
        inventory = refresh(json.loads(args.manifest.read_text()), args.profile)
        with tempfile.NamedTemporaryFile("w", dir=args.output.parent, delete=False) as out:
            pending = Path(out.name)
            json.dump(inventory, out)
            out.flush()
            os.fsync(out.fileno())
        pending.replace(args.output)
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as err:
        print(f"IAM inventory refresh failed ({type(err).__name__}); check profile and manifest", file=sys.stderr)
        return 2
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
