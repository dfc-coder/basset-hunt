# Basset Hunt

Basset Hunt is an open-source Rust CLI that detects exposed credentials in files, staged changes, and Git history, reports where they appear, and checks their status against a trusted inventory. Findings are JSON Lines with a detector ID, credential classification, path and line. Git findings include a repository, commit and blob. Optional owner inventory adds credential status, permissions and a rotation runbook.

## Quick start

Use stable Rust with Cargo (edition 2024), and Git 2.36 or newer for Git modes. The first build downloads crates. Scanning runs locally.

```bash
cargo build --release --locked
cargo install --path . --locked
basset rules
basset rules --list
basset fs ./service
basset git ./service
basset staged ./service
printf '%s\n' 'ordinary configuration' | basset stdin --name deployment.env
```

Git history mode requires a full local clone. It scans regular-file versions reachable from all local refs, including fetched branches, tags and detached HEAD. It reads raw blobs and scans each distinct (path, blob) once, including files later deleted. The revision is one commit containing that version, not necessarily the original introduction. Staged mode reads the changed index blobs even when the working copy differs. Submodules need their own scan. Git LFS pointer files contain only pointers; scan the materialized LFS assets separately.

## Detection and triage

The pinned `secrets_scanner` 0.2.3 library supplies the embedded rule catalog, keyword matching, entropy checks and allowlists. Its default catalog documents 988 active rules. Multiple rules can detect variants of the same credential type. `basset rules` measures the locally compiled catalog, and scans fail if fewer than 800 rules load. See the [upstream catalog and licensing notes](https://docs.rs/crate/secrets_scanner/0.2.3/source/README.md).

Stdout carries one JSON object per finding. Stderr carries coverage diagnostics. Match text and source lines are excluded. Paths, source names, owner labels and runbook references are included verbatim as JSON strings and should be suitable for the intended report audience. Put tokens and signed URLs in content, never in location or inventory metadata.

| Exit | Meaning |
|---|---|
| 0 | Scan completed with zero findings matching the selected filter |
| 1 | One or more findings matched the filter |
| 2 | Input, configuration or coverage error. Earlier output can be partial |

Each raw document is capped at 8 MiB by default. Set `--max-bytes` to change it (maximum 256 MiB). Export records stream independently; raw stdin is one bounded document. Oversized documents and detector truncation mark the run incomplete. Directory scans include hidden files and inspect regular files only, skipping symlinks and .git entries. Archives and model weights are not recursively decoded. Use a stable local snapshot when scanning a concurrently changing directory.

## Inventory-backed verification

`verified` means that the exact detected bytes match an HMAC-SHA-256 fingerprint whose trusted inventory record said **active** at `checked_at`. Basset Hunt does not authenticate with discovered values or contact issuers. A record can become outdated before it expires. Permissions are supplied by the owner. A provider credential ID or a masked suffix alone cannot establish this match.

Create the correlation key once, keep it in your secret manager, and inject it into both your inventory exporter and authorized scan jobs as `BASSET_HMAC_KEY` (64 hex characters). Existing installations can continue using `CREDCHECK_HMAC_KEY` as a fallback. For a disposable local demonstration:

```bash
export BASSET_HMAC_KEY="$(openssl rand -hex 32)"
```

The owner-side exporter computes HMAC over the exact credential bytes, without a trailing newline unless it belongs to the value. The `fingerprint` command accepts these bytes on stdin. Record the actual observation time from your credential management system. A minimal inventory is a JSON array:

```json
[
  {
    "fingerprint": "<64 lowercase hex characters from the owner exporter>",
    "state": "active",
    "checked_at": 1795600000,
    "owner": "payments-platform",
    "permissions": ["invoices:read"],
    "rotation_runbook": "runbooks/payments-api-key"
  }
]
```

```bash
basset git ./service --inventory /secure/credential-inventory.json --results=verified
basset fs ./assets --inventory /secure/credential-inventory.json --only-verified
```

Use an inventory file controlled independently of the scanned repository. Its integrity establishes the trust in status and permissions. States are `verified`, `inactive`, `revoked`, `stale` and `unknown`. All status records expire after 86,400 seconds by default (`--max-age-seconds`); future observations are also stale. Absent matches and path-only detections remain unknown. Without a correlation key, the scanner omits fingerprint values. Verified-only runs require both the inventory and key. Use the default all-results mode to gate new leaks, including secrets missing from inventory.

### Refresh AWS IAM status before a scan

The optional owner-side adapter queries the AWS control plane using a separate audit profile. It checks the account and reads key status for the IAM users named in a trusted provisioning manifest. At provisioning, bind each key ID to the HMAC of its **secret access key bytes**. A public ID alone must never be used as the verification fingerprint. The manifest has this structure:

```json
{
  "account": "123456789012",
  "keys": [{
    "iam_user": "release-bot",
    "key_id": "<provisioned access key ID>",
    "fingerprint": "<HMAC of the corresponding secret access key>",
    "owner": "release-engineering",
    "rotation_runbook": "runbooks/release-bot"
  }]
}
```

With Python 3.10+, AWS CLI v2 and a profile allowed to call `iam:ListAccessKeys` for the named users:

```bash
python3 adapters/refresh_iam.py /secure/aws-bindings.json /secure/aws-inventory.json --profile audit && \
  basset git ./service --inventory /secure/aws-inventory.json --only-verified
```

An active entry reflects AWS's response at the recorded time. Inactive and expired provider keys map to inactive. Missing IDs are omitted. Any API error aborts the refresh before replacing the inventory file. The adapter reports only provisioned bindings and uses owner-supplied permission labels. Coverage is limited to long-lived AWS IAM user keys whose secret material the detector captures. Other providers can produce the same inventory schema. See the [AWS command reference](https://docs.aws.amazon.com/cli/latest/reference/iam/list-access-keys.html).

## Source inputs

| Source | Supported input |
|---|---|
| Code, configs, mounted object storage, downloaded Hugging Face files | `basset fs PATH` |
| Repositories, locally available forks, gist clones, Hugging Face Git histories | `basset git PATH` per clone |
| GitHub issue, PR and review-comment exports | Local JSON array with title, body or diff hunk. Use the jq adapter below |
| Gists | Local gist JSON with complete file content, or a local clone |
| Slack | Local day JSON from a Slack export. Text messages only |
| Other collaboration services and exported objects | One JSON Lines record per document |

Use explicit exports for org-wide audits. The scanner consumes the local collection. It does not crawl organizations, discover public forks or unreachable objects, download cloud accounts, or decompress attachments. Include the full set of authorized repositories, discussions, pages and attachments in your export when that coverage matters. Mount or materialize Hugging Face snapshot data as regular files; some cache layouts use symlinks.

```bash
set -o pipefail
jq -c -f adapters/github-discussions.jq issues.json | basset records
jq -c -f adapters/gists.jq gist.json | basset records
jq -c --arg path 'release/2026-11-01.json' -f adapters/slack-day.jq slack-day.json | basset records
```

Each record uses `source`, `path`, optional `revision` and string `content`. Malformed or oversized records produce exit 2. Lines and columns refer to the decoded document, so multiline messages and private keys retain their boundaries.

## CI and containers

The included GitHub Actions workflow builds the scanner, runs the integration suite and scans the full checkout. Jenkins uses a preinstalled `basset` and a full clone. To enforce a gate across application repositories, install a separately reviewed scanner build in the runner. Keep the HMAC key and trusted inventory out of untrusted pull-request jobs. Default candidate detection works without either.

For a local pre-commit configuration after `cargo install --path .`:

```yaml
repos:
  - repo: local
    hooks:
      - id: basset
        name: Scan staged credentials
        entry: basset staged .
        language: system
        pass_filenames: false
        always_run: true
```

An installable Rust hook manifest is also included for a versioned repository.

```bash
docker build -t basset:local .
docker run --rm --network=none --read-only --user "$(id -u):$(id -g)" \
  -v "$PWD:/data:ro" basset:local git /data
```

The same build and run commands work with Podman. For rootless Podman use `--userns=keep-id` with the user option to preserve host ownership. The runtime requires read access to the mounted files.

## Development and license

```bash
cargo build --release --locked
cargo test --locked
python3 tests/test_iam.py
python3 tests/e2e.py target/release/basset
```

The Python integration suite generates synthetic values and exercises the compiled CLI. `Cargo.lock` is versioned; use `--locked` for reproducible builds, installs and tests. Update the lockfile intentionally when dependencies change.

Original project code is MIT-licensed. The detector library and its bundled rule sources retain their upstream licenses and notices. The optional extended rule pack and HTTP updater are disabled.

[Development roadmap (Español)](docs/plan-de-actualizacion.md)
