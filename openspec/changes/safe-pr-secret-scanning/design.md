# Design

## Context

See `proposal.md` for motivation and the two capability specs for observable behavior. `src/main.rs` builds `Scanner::from_bundled()` with `ScanConfig::default()`, which currently honors inline allow markers. `src/git.rs` enumerates all reachable commits and scans each changed blob; it has no base/head mode. Git invocations already disable external diff and textconv and disable network protocols. The current GitHub workflow uses full history for both push and pull-request events. `secrets_scanner` 0.2.3 provides a SARIF writer, but its default fingerprint hashes the detected value and its document omits invocation success state, so it cannot be used unchanged.

Reference behavior was inspected at TruffleHog v3.100.1: `pkg/gitparse/gitparse.go`, `pkg/sources/git/git.go`, `pkg/output/sarif.go`, and `action.yml`. Its Git range is `head ^base`; it requests `git log --patch` without a merge-diff format, so Git emits no patch for merge commits by default. TruffleHog assembles patch content from added and contextual lines. This change adopts the reference's merge-commit scope but retains full-blob scanning plus added-line filtering for multiline detection. It will not copy reference code or detector definitions; its license is AGPL-3.0, while this project is MIT.

## Goals / Non-Goals

**Goals:**

- Add a local, explicit Git range scan that examines non-merge commits in the range and reports only findings whose matched span overlaps newly added lines.
- Preserve enough unchanged hunk context to detect multiline secrets, then filter results by whether the detected span touches an added line.
- Reuse Basset's bundled detector engine, current HMAC inventory semantics, per-document size limit, and exit codes.
- Emit secret-safe SARIF for range scans, and make partial coverage visible to both the caller and SARIF consumers.
- Make inline suppression behavior uniform and fail-safe across all content scanning sources.

**Non-Goals:**

- Change full-history blob scanning, staged-index semantics, JSONL default output, inventory format, or offline-only verification.
- Scan commit messages, authors, signatures, notes, or deleted lines in range mode. These are differences from TruffleHog to record for later prioritization.
- Add base64/Unicode/archive decoding, new detectors, provider verification, or remote repository/source connectors.
- Vendor, port, or redistribute TruffleHog code or detectors, or add it as a runtime dependency.

## Decisions

### Separate explicit range mode from history mode

Resolve base and head to commit object IDs within the selected repository, reject invalid/equal commits, and reject shallow repositories before enumerating commits. This prevents a truncated history boundary from being mistaken for a true root. Enumerate commits reachable from head but not base. Scan each ordinary commit against its single parent; compare root commits against the empty tree. Do not generate a finding diff for merge commits, matching the reference's default `git log --patch` behavior. Their non-base ancestor commits are still in the range. A secret introduced only in a merge-conflict resolution is a known coverage gap. Read each new blob with the existing local Git object path and scan the complete blob, but retain a finding only when its detected byte span intersects an added line. This preserves full-file context for multiline rules while preventing unchanged findings in a touched file from blocking a PR.

An added-line-range approach was chosen over scanning only patch text: patch-only input can break multiline credentials when unchanged context is needed, while scanning whole changed blobs without filtering reintroduces stale findings. The full-history command remains unchanged and continues to scan historical blobs.

Resolve user-provided refs with Git's end-of-options boundary, validate the resolved object IDs as commits, and pass arguments as an argument vector rather than through a shell. Keep external diff and textconv disabled, network protocols disabled, and never execute repository hooks or content. If the repository is shallow, the range cannot be resolved, a patch cannot be mapped safely, or a changed binary input has no line mapping, mark the scan incomplete and return exit 2 rather than claiming success.

### Configure every scanner to ignore inline allow markers

Construct the bundled scanner with its existing configuration type and set `honor_allow_markers=false`, preserving all other defaults. Do not add a flag that re-enables suppression. Apply this single scanner configuration before dispatching to `fs`, `stdin`, `records`, `staged`, full-history, or range scans. This makes a marker in the scanned content unable to control whether its own finding is reported.

### Build a narrow SARIF writer instead of forwarding the library writer

Keep JSONL as the default. The range SARIF path will create a bounded result collection and serialize the SARIF 2.1.0 subset needed by GitHub: tool/rules, generic messages, repository-relative URIs, line regions, commit metadata, partial fingerprints, and `runs[].invocations[].executionSuccessful`. Do not serialize `Finding::matched`, inventory fingerprints, or source context.

The built-in `write_sarif` is not reused as-is because its partial fingerprint includes a SHA-256 of the secret. Use a deterministic identity made only from rule ID, repository-relative path, line, and start column; never include the matched bytes or any digest of them. This may create a new alert identity when a finding moves to a different line, but avoids an offline guessing oracle when a fork PR has no HMAC key. Keep the existing finding exit status (0 clean, 1 findings, 2 incomplete); on partial results emit SARIF with `executionSuccessful=false` before returning 2. Bound SARIF buffering with a global result cap; reaching the cap is incomplete, retains the results collected so far, and exits 2.

### Keep CI least-privileged and fork-safe

For `pull_request`, checkout enough history to resolve the event's base/head SHAs and invoke range mode. Keep `pull_request`, not `pull_request_target`. The scan job needs no write token and receives no secrets. Upload SARIF only in a separate step/job with the narrow `security-events: write` permission when the event is eligible and repository code scanning is enabled. For forks or repositories where upload is unavailable, upload the SARIF file as a normal artifact using the read-only workflow context. Ensure the artifact-preservation step runs after an exit-2 scan. Keep the existing full-history push scan unchanged in this change; a later decision may separate scheduled/manual history audits from push checks.

### Update the roadmap without claiming feature parity

Revise `docs/plan-de-actualizacion.md` so M3 names the base/head added-line contract, safe SARIF, and the global no-inline-suppression policy. Record that TruffleHog's `unknown` (verification request failed) is not Basset's `unknown` (no matching inventory evidence). Pin v3.100.1 for the future local comparison and run it with remote verification disabled. Keep commit metadata scanning and decoding as deferred gaps rather than implying parity.

## Risks / Trade-offs

- [Patch line mapping can be confused by unusual paths, binary files, or malformed patch output] → Use NUL-delimited Git metadata, literal pathspecs, test special paths and root commits, disable external diff/textconv, omit merge diffs, and mark ambiguous or binary cases incomplete.
- [Secrets added only while resolving a merge conflict are not found by range mode] → Match TruffleHog v3.100.1 by omitting merge-result diffs; retain the full-history scan as a separate audit path and document this limitation.
- [Untrusted PR data can cause excessive parsing or SARIF memory use] → Enforce commit, changed-file, per-document byte, patch-hunk and global SARIF finding caps; reaching a limit or encountering shallow history is exit 2, never a clean result.
- [Location-only fingerprints can change when code moves] → Accept the loss of move-stable identity rather than hash secret bytes; document this limitation and test repeat scans at an unchanged location.
- [Disabling inline suppression may increase reported findings for existing users] → Treat it as an intentional behavior change, document it, and require explicit owner-managed inventory or future reviewed suppression configuration rather than in-band comments.
- [GitHub SARIF upload may be unavailable for forks or repositories without code scanning] → Always preserve a local SARIF artifact and do not elevate permissions to force upload.
- [TruffleHog license or detector data could be copied inadvertently] → Use only versioned public documentation and an external binary for the deferred comparison; do not import code, rules, or bundled detector data.

## Migration Plan

1. Add range mode and no-inline-suppression behavior while retaining `git`, `staged`, and JSONL defaults.
2. Add SARIF output, focused CLI and end-to-end tests, and secret-leak assertions over stdout, stderr, and SARIF.
3. Update the pull-request workflow to use event base/head, preserve artifacts on incomplete scans, and use least-privilege upload handling.
4. Update the roadmap and README with the behavior change, CLI usage, limitations, and the pinned external comparison version.
5. Rollback is a normal revert of the change. This restores prior full-history CI and inline-marker behavior; no inventory or persisted data migration is required.
