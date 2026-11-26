# Spec Delta

## Purpose

Permite revisar los secretos introducidos por un rango de commits y publicar resultados consumibles por GitHub sin exponer el valor detectado ni ocultar análisis incompletos.

## ADDED Requirements

### Requirement: Explicit commit range
The CLI SHALL accept distinct base and head commits for a Git range scan. It MUST resolve both to commits in the selected local repository and MUST fail with exit code 2 if either is invalid, unavailable, or equal, or if the repository is shallow; it MUST NOT silently fall back to a full-history scan.

#### Scenario: Valid range
- **WHEN** the user scans a repository with valid distinct base and head commits
- **THEN** Basset scans the commit range and returns findings for the range only

#### Scenario: Invalid or equal commits
- **WHEN** either commit cannot be resolved or base and head resolve to the same commit
- **THEN** the command reports an incomplete/error outcome with exit code 2 and does not claim a clean scan

#### Scenario: Shallow repository
- **WHEN** the selected repository has shallow history
- **THEN** the command reports an incomplete outcome with exit code 2 rather than treating a truncated history boundary as a root commit

### Requirement: Scan added lines in every commit in range
The range scan SHALL examine added lines from each non-merge commit reachable from head but not base, including content added in an intermediate commit and removed by a later commit in the same range. Root commits SHALL be compared with the empty tree. Merge commits SHALL NOT produce a result diff; their non-base ancestor commits remain in the range. Therefore, secrets introduced only while resolving a merge conflict are outside range-scan coverage. The scan MUST NOT report unchanged context or deleted lines as additions. The existing full-history mode SHALL continue scanning historical file blobs independently of this range behavior.

#### Scenario: Secret added in the range
- **WHEN** a commit in the range adds a line containing a detectable secret
- **THEN** the range scan reports that secret with the repository-relative file path, line, and introducing commit

#### Scenario: Existing secret in a modified file
- **WHEN** a commit changes one line in a file that already contains a detectable secret on an unchanged line
- **THEN** the range scan does not report the unchanged secret

#### Scenario: Secret added and then removed within the range
- **WHEN** one commit adds a detectable secret and a later commit in the same range removes it
- **THEN** the range scan still reports the added exposure from the commit that introduced it

#### Scenario: Merge imports do not create range findings
- **WHEN** a merge commit in the range imports a secret from a commit reachable from base
- **THEN** the merge commit produces no finding; non-merge commits in the range are still scanned

#### Scenario: Merge-resolution-only secrets are outside coverage
- **WHEN** a secret exists only in the conflict resolution recorded by a merge commit
- **THEN** the range scan does not report it from the merge commit

#### Scenario: Full-history audit remains available
- **WHEN** the user runs the existing full-history command
- **THEN** Basset continues to report findings in historical blobs, including blobs no longer present at head

### Requirement: SARIF output for range findings
The range scan SHALL optionally emit valid SARIF 2.1.0 with repository-relative artifact URIs and line regions. SARIF messages, properties, and fingerprints MUST NOT contain the detected value or a direct or unkeyed cryptographic hash of that value. JSONL remains the default output format.

#### Scenario: SARIF contains a finding
- **WHEN** a range scan finds a secret and SARIF output is selected
- **THEN** the output is valid SARIF 2.1.0 and identifies the rule, repository-relative path, line, and commit without including secret bytes

#### Scenario: Fingerprint does not expose secret material
- **WHEN** a SARIF result is created for a secret, including when no HMAC key is configured
- **THEN** its fingerprint is derived only from non-secret finding identity data and excludes the secret bytes and any hash computed from them

#### Scenario: JSONL default is preserved
- **WHEN** the user runs a scan without selecting SARIF
- **THEN** the existing JSONL output remains the default

### Requirement: Partial scans are explicitly incomplete
The range scan SHALL preserve any findings already produced when an input cannot be fully analyzed, mark the SARIF invocation unsuccessful, and return exit code 2. A partial scan MUST NOT be represented as a successful clean result.

#### Scenario: Input cannot be fully scanned
- **WHEN** the range scan encounters an unreadable, unsupported, oversized, or truncated input
- **THEN** it retains available results, records the incomplete condition in SARIF, and exits with code 2

#### Scenario: Complete scan with findings
- **WHEN** the range scan completes without errors and reports findings
- **THEN** it returns the existing findings exit code 1

### Requirement: GitHub pull request workflow uses the range scan safely
The GitHub pull request workflow SHALL pass explicit base and head commits to the range scan and use least-privilege permissions. It MUST NOT use `pull_request_target` to execute untrusted pull request content or expose repository secrets to fork code. When the event token cannot upload SARIF, the workflow SHALL retain the result as an artifact without elevating permissions.

#### Scenario: Trusted pull request uploads SARIF
- **WHEN** a pull request event has the permissions required by the repository's code-scanning configuration
- **THEN** the workflow uploads SARIF for the pull request range

#### Scenario: Fork pull request lacks upload permission
- **WHEN** a fork pull request cannot upload SARIF
- **THEN** the scan still runs without secrets or elevated permissions and preserves SARIF as a downloadable artifact

#### Scenario: PR range is unavailable
- **WHEN** the workflow cannot fetch or resolve the event's base or head commit
- **THEN** it fails visibly with exit code 2 rather than running a full-history scan and presenting it as the PR result
