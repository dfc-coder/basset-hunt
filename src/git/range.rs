use std::io::BufRead;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::str;

use anyhow::{ensure, Context, Result};

use super::{is_oid, metadata, Objects};
use crate::{Audit, Location};

const MAX_RANGE_COMMITS: usize = 1_000;
const MAX_COMMIT_CHANGES: usize = 1_000;
const MAX_RANGE_CHANGES: usize = 1_000;
const MAX_DIFF_HUNKS: usize = 100_000;
const MAX_DIFF_HUNK_HEADER_BYTES: u64 = 128;

struct Change {
    old_mode: String,
    new_mode: String,
    old_oid: String,
    new_oid: String,
    path: Vec<u8>,
}

fn repository_root(repo: &Path) -> Result<PathBuf> {
    let bare = metadata(
        repo,
        &["rev-parse", "--is-bare-repository"],
        |mut reader| {
            let mut answer = String::new();
            reader.read_line(&mut answer)?;
            Ok(answer.trim() == "true")
        },
    )?;
    if bare {
        return Ok(repo.canonicalize()?);
    }
    let top = metadata(repo, &["rev-parse", "--show-toplevel"], |mut reader| {
        let mut path = String::new();
        reader.read_line(&mut path)?;
        Ok(PathBuf::from(path.trim()))
    })?;
    Ok(top.canonicalize()?)
}

fn is_shallow_repository(repo: &Path) -> Result<bool> {
    metadata(
        repo,
        &["rev-parse", "--is-shallow-repository"],
        |mut reader| {
            let mut answer = String::new();
            reader.read_line(&mut answer)?;
            match answer.trim() {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => anyhow::bail!("invalid shallow-repository status"),
            }
        },
    )
}

fn resolve_commit(repo: &Path, revision: &str) -> Result<String> {
    ensure!(!revision.is_empty(), "empty Git revision");
    let expression = format!("{revision}^{{commit}}");
    let args = [
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        &expression,
    ];
    metadata(repo, &args, |mut reader| {
        let mut oid = String::new();
        reader.read_line(&mut oid)?;
        let oid = oid.trim();
        ensure!(is_oid(oid), "invalid Git commit ID");
        Ok(oid.to_owned())
    })
}

fn revisions(repo: &Path, base: &str, head: &str) -> Result<Vec<String>> {
    let excluded = format!("^{base}");
    let args = ["rev-list", "--reverse", "--topo-order", head, &excluded];
    metadata(repo, &args, |reader| {
        let mut commits = Vec::new();
        for line in reader.lines() {
            let oid = line?;
            ensure!(is_oid(&oid), "invalid Git commit ID");
            ensure!(
                commits.len() < MAX_RANGE_COMMITS,
                "Git range exceeds commit limit"
            );
            commits.push(oid);
        }
        Ok(commits)
    })
}

fn parents(repo: &Path, commit: &str) -> Result<Vec<String>> {
    metadata(
        repo,
        &["rev-list", "--parents", "-n", "1", commit],
        |mut reader| {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let mut fields = line.split_whitespace();
            ensure!(fields.next() == Some(commit), "invalid Git parent list");
            let parents = fields.map(str::to_owned).collect::<Vec<_>>();
            ensure!(
                parents.iter().all(|oid| is_oid(oid)),
                "invalid Git parent ID"
            );
            ensure!(parents.len() <= 128, "commit has too many parents");
            Ok(parents)
        },
    )
}

fn changes(repo: &Path, parent: Option<&str>, commit: &str) -> Result<Vec<Change>> {
    let mut args = vec![
        "diff-tree".to_owned(),
        "-r".to_owned(),
        "--raw".to_owned(),
        "-z".to_owned(),
        "--no-abbrev".to_owned(),
        "--no-renames".to_owned(),
        "--no-relative".to_owned(),
        "--no-ext-diff".to_owned(),
        "--no-textconv".to_owned(),
        "--ignore-submodules=all".to_owned(),
        "--no-commit-id".to_owned(),
        "--diff-filter=AMT".to_owned(),
    ];
    if parent.is_none() {
        args.push("--root".to_owned());
    }
    if let Some(parent) = parent {
        args.push(parent.to_owned());
    }
    args.extend([commit.to_owned(), "--".to_owned()]);
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    metadata(repo, &refs, |reader| {
        let mut fields = reader.split(0);
        let mut changes = Vec::new();
        while let Some(header) = fields.next() {
            let header = header?;
            if header.is_empty() {
                continue;
            }
            let path = fields.next().context("missing Git change path")??;
            let header = str::from_utf8(&header).context("invalid Git change header")?;
            let parts = header.split_whitespace().collect::<Vec<_>>();
            ensure!(
                parts.len() == 5 && parts[0].starts_with(':'),
                "invalid Git change header"
            );
            let status = parts[4];
            if !matches!(status, "A" | "M" | "T") {
                continue;
            }
            ensure!(is_oid(parts[3]), "invalid changed blob ID");
            ensure!(
                changes.len() < MAX_COMMIT_CHANGES,
                "commit has too many changed files"
            );
            changes.push(Change {
                old_mode: parts[0][1..].to_owned(),
                new_mode: parts[1].to_owned(),
                old_oid: parts[2].to_owned(),
                new_oid: parts[3].to_owned(),
                path,
            });
        }
        Ok(changes)
    })
}

fn parse_range(value: &str, prefix: char) -> Result<(usize, usize)> {
    let value = value
        .strip_prefix(prefix)
        .context("invalid diff hunk range")?;
    let (start, count) = match value.split_once(',') {
        Some((start, count)) => (start.parse()?, count.parse()?),
        None => (value.parse()?, 1),
    };
    Ok((start, count))
}

fn parse_hunk_header(line: &[u8]) -> Result<(usize, usize, usize, usize)> {
    let body = line
        .strip_prefix(b"@@ ")
        .context("invalid diff hunk header")?;
    let end = body
        .windows(3)
        .position(|window| window == b" @@")
        .context("invalid diff hunk header")?;
    let ranges = str::from_utf8(&body[..end]).context("non-UTF-8 diff ranges")?;
    let mut ranges = ranges.split_whitespace();
    let (old_start, old_count) =
        parse_range(ranges.next().context("missing old diff range")?, '-')?;
    let (new_start, new_count) =
        parse_range(ranges.next().context("missing new diff range")?, '+')?;
    ensure!(ranges.next().is_none(), "invalid diff hunk header");
    Ok((old_start, old_count, new_start, new_count))
}

fn parse_added_ranges(
    reader: &mut impl BufRead,
    max_bytes: u64,
) -> Result<Vec<RangeInclusive<usize>>> {
    let mut added = Vec::new();
    let mut old_left = 0usize;
    let mut new_left = 0usize;
    let mut in_hunk = false;
    let mut saw_hunk = false;
    let mut hunks = 0usize;
    let mut total = 0u64;
    let limit = max_bytes
        .saturating_mul(4)
        .saturating_add(65536)
        .saturating_add(MAX_DIFF_HUNKS as u64 * MAX_DIFF_HUNK_HEADER_BYTES);
    let mut line = Vec::new();
    loop {
        line.clear();
        let count = reader.read_until(b'\n', &mut line)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .context("diff size overflow")?;
        ensure!(total <= limit, "diff exceeds range parsing limit");
        let line = line.strip_suffix(b"\n").unwrap_or(&line);
        if line.starts_with(b"Binary files ") || line.starts_with(b"GIT binary patch") {
            anyhow::bail!("binary diff has no line map");
        }
        if line.starts_with(b"@@ ") {
            ensure!(
                !in_hunk || (old_left == 0 && new_left == 0),
                "truncated diff hunk"
            );
            hunks += 1;
            ensure!(hunks <= MAX_DIFF_HUNKS, "too many diff hunks");
            ensure!(
                line.len() <= MAX_DIFF_HUNK_HEADER_BYTES as usize,
                "diff hunk header too large"
            );
            let (old_start, old_count, new_start, new_count) = parse_hunk_header(line)?;
            ensure!(old_count == 0 || old_start > 0, "invalid old diff line");
            if new_count > 0 {
                ensure!(new_start > 0, "invalid new diff line");
                let end = new_start
                    .checked_add(new_count - 1)
                    .context("diff line overflow")?;
                added.push(new_start..=end);
            }
            old_left = old_count;
            new_left = new_count;
            in_hunk = old_left > 0 || new_left > 0;
            saw_hunk = true;
            continue;
        }
        if !in_hunk {
            continue;
        }
        if line.starts_with(b"\\") {
            continue;
        }
        match line.first() {
            Some(b'+') if new_left > 0 => new_left -= 1,
            Some(b'-') if old_left > 0 => old_left -= 1,
            Some(b' ') if old_left > 0 && new_left > 0 => {
                old_left -= 1;
                new_left -= 1;
            }
            _ => anyhow::bail!("malformed diff hunk"),
        }
        if old_left == 0 && new_left == 0 {
            in_hunk = false;
        }
    }
    ensure!(!in_hunk, "truncated diff hunk");
    ensure!(saw_hunk, "changed text blob has no diff hunk");
    Ok(added)
}

fn line_ranges(
    repo: &Path,
    parent: Option<&str>,
    commit: &str,
    path: &str,
    max_bytes: u64,
) -> Result<Vec<RangeInclusive<usize>>> {
    let mut args = if let Some(parent) = parent {
        vec![
            "diff".to_owned(),
            "--no-ext-diff".to_owned(),
            "--no-textconv".to_owned(),
            "--no-renames".to_owned(),
            "--no-color".to_owned(),
            "--unified=0".to_owned(),
            parent.to_owned(),
            commit.to_owned(),
        ]
    } else {
        vec![
            "diff-tree".to_owned(),
            "--root".to_owned(),
            "--no-commit-id".to_owned(),
            "-p".to_owned(),
            "--no-ext-diff".to_owned(),
            "--no-textconv".to_owned(),
            "--no-renames".to_owned(),
            "--no-color".to_owned(),
            "--unified=0".to_owned(),
            commit.to_owned(),
        ]
    };
    args.extend(["--".to_owned(), path.to_owned()]);
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    metadata(repo, &refs, |mut reader| {
        parse_added_ranges(&mut reader, max_bytes)
    })
}

pub(crate) fn scan<W: std::io::Write>(
    repo: &Path,
    base: &str,
    head: &str,
    audit: &mut Audit<W>,
) -> Result<()> {
    let repo = repository_root(repo)?;
    let repo_label = repo.to_string_lossy().into_owned();
    audit.set_sarif_root(&repo_label);
    if is_shallow_repository(&repo)? {
        let loc = Location {
            source: &repo_label,
            path: "<range>",
            revision: None,
            blob: None,
        };
        audit.skip(&loc, "Git range requires complete repository history")?;
        return Ok(());
    }
    let base = resolve_commit(&repo, base)?;
    let head = resolve_commit(&repo, head)?;
    ensure!(base != head, "base and head resolve to the same commit");
    let commits = revisions(&repo, &base, &head)?;
    let mut objects = Objects::open(&repo)?;
    let mut processed_changes = 0usize;

    for commit in commits {
        let parents = match parents(&repo, &commit) {
            Ok(parents) => parents,
            Err(_) => {
                let loc = Location {
                    source: &repo_label,
                    path: "<commit>",
                    revision: Some(&commit),
                    blob: None,
                };
                audit.skip(&loc, "could not read commit parents")?;
                continue;
            }
        };
        if parents.len() > 1 {
            continue;
        }
        let parent = parents.first().map(String::as_str);
        let changes = match changes(&repo, parent, &commit) {
            Ok(changes) => changes,
            Err(_) => {
                let loc = Location {
                    source: &repo_label,
                    path: "<commit>",
                    revision: Some(&commit),
                    blob: None,
                };
                audit.skip(&loc, "could not enumerate commit changes")?;
                continue;
            }
        };

        for change in changes {
            processed_changes += 1;
            if processed_changes > MAX_RANGE_CHANGES {
                let loc = Location {
                    source: &repo_label,
                    path: "<range>",
                    revision: Some(&commit),
                    blob: None,
                };
                audit.skip(&loc, "Git range exceeds changed-file limit")?;
                return Ok(());
            }
            if !matches!(change.new_mode.as_str(), "100644" | "100755")
                || change.old_oid == change.new_oid
            {
                continue;
            }
            let path = match str::from_utf8(&change.path) {
                Ok(path) => path,
                Err(_) => {
                    let loc = Location {
                        source: &repo_label,
                        path: "<non-utf8-path>",
                        revision: Some(&commit),
                        blob: Some(&change.new_oid),
                    };
                    audit.skip(&loc, "Git path is not UTF-8")?;
                    continue;
                }
            };
            let loc = Location {
                source: &repo_label,
                path,
                revision: Some(&commit),
                blob: Some(&change.new_oid),
            };
            let new_size = match objects.query("info", &change.new_oid) {
                Ok(size) => size,
                Err(_) => {
                    audit.skip(&loc, "could not read changed Git blob")?;
                    continue;
                }
            };
            if new_size == 0 {
                continue;
            }
            if new_size > audit.limit {
                audit.skip(&loc, "Git blob exceeds --max-bytes")?;
                continue;
            }
            if matches!(change.old_mode.as_str(), "100644" | "100755") && is_oid(&change.old_oid) {
                match objects.query("info", &change.old_oid) {
                    Ok(size) if size <= audit.limit => {}
                    Ok(_) => {
                        audit.skip(&loc, "parent Git blob exceeds --max-bytes")?;
                        continue;
                    }
                    Err(_) => {
                        audit.skip(&loc, "could not read parent Git blob")?;
                        continue;
                    }
                }
            }
            let ranges = match line_ranges(&repo, parent, &commit, path, audit.limit) {
                Ok(ranges) if ranges.is_empty() => continue,
                Ok(ranges) => ranges,
                Err(_) => {
                    audit.skip(&loc, "could not map added Git lines")?;
                    continue;
                }
            };
            if objects
                .scan_added(&change.new_oid, loc, &ranges, audit)
                .is_err()
            {
                let loc = Location {
                    source: &repo_label,
                    path,
                    revision: Some(&commit),
                    blob: Some(&change.new_oid),
                };
                audit.skip(&loc, "could not scan changed Git blob")?;
                return Ok(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_added_ranges;
    use std::io::Cursor;

    #[test]
    fn parses_added_lines_from_unified_zero_diff() {
        let patch =
            b"diff --git a/x b/x\n@@ -1 +1,2 @@\n-old\n+new\n+another\n@@ -4,0 +6 @@\n+last\n";
        let mut reader = Cursor::new(patch);
        assert_eq!(
            parse_added_ranges(&mut reader, 1024).unwrap(),
            vec![1..=2, 6..=6]
        );
    }

    #[test]
    fn ignores_non_utf8_hunk_function_context() {
        let mut patch = Cursor::new(b"@@ -0,0 +1 @@ \xff\n+secret\n");
        assert_eq!(parse_added_ranges(&mut patch, 1024).unwrap(), vec![1..=1]);
    }

    #[test]
    fn accepts_hunk_overhead_for_newline_dense_changes() {
        let mut patch = Vec::new();
        for line in 1..=10_000 {
            patch.extend_from_slice(format!("@@ -{line} +{line} @@\n-old\n+new\n").as_bytes());
        }
        let mut patch = Cursor::new(patch);
        assert_eq!(
            parse_added_ranges(&mut patch, 20_000).unwrap().len(),
            10_000
        );
    }

    #[test]
    fn rejects_binary_malformed_truncated_and_oversized_diffs() {
        let mut binary = Cursor::new(b"Binary files a/x and b/x differ\n");
        assert!(parse_added_ranges(&mut binary, 1024).is_err());

        let mut malformed = Cursor::new(b"@@ broken @@\n+x\n");
        assert!(parse_added_ranges(&mut malformed, 1024).is_err());

        let mut truncated = Cursor::new(b"@@ -1,1 +1,2 @@\n-old\n+new\n");
        assert!(parse_added_ranges(&mut truncated, 1024).is_err());

        let mut deletion_only = Cursor::new(b"@@ -1,1 +0,0 @@\n-old\n");
        assert!(parse_added_ranges(&mut deletion_only, 1024)
            .unwrap()
            .is_empty());

        let oversized = vec![b'x'; 13 * 1024 * 1024];
        let mut oversized = Cursor::new(oversized);
        assert!(parse_added_ranges(&mut oversized, 1).is_err());
    }
}
