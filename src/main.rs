mod baseline;
mod evidence;
mod git;
mod inputs;
mod sarif;

use std::io::{self, BufWriter, Read, Write};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use secrets_scanner::{ScanConfig, Scanner};
use serde::Serialize;
use serde_json::json;

#[derive(Parser)]
#[command(name = "basset", version, about = "Scan local content and correlate findings with trusted credential inventory")]
struct Cli {
    #[command(subcommand)]
    command: Source,
    #[arg(long, global = true, value_name = "FILE", conflicts_with = "baseline")]
    write_baseline: Option<PathBuf>,
    #[arg(long, global = true, value_name = "FILE", conflicts_with = "write_baseline")]
    baseline: Option<PathBuf>,
    #[arg(long, global = true)]
    inventory: Option<PathBuf>,
    #[arg(long, global = true, default_value_t = 86400)]
    max_age_seconds: u64,
    #[arg(long, global = true, value_enum, default_value = "all", conflicts_with = "only_verified")]
    results: Filter,
    #[arg(long, global = true)]
    only_verified: bool,
    /// Maximum bytes per document. Oversized inputs cause exit 2.
    #[arg(long, global = true, default_value_t = 8388608, value_parser = clap::value_parser!(u64).range(1..=268435456))]
    max_bytes: u64,
    /// Add validated detection rules from a TOML file to the bundled catalog.
    #[arg(long, global = true, value_name = "FILE")]
    rules: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Filter { All, Verified }

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum RangeFormat { Jsonl, Sarif }

#[derive(Subcommand)]
enum Source {
    /// Scan a local file or directory, including hidden files.
    Fs { path: PathBuf },
    /// Scan stdin as a single document.
    Stdin { #[arg(long, default_value = "stdin.txt")] name: String },
    /// Stream exported documents as JSON Lines from stdin.
    Records,
    /// Scan file versions reachable from local Git refs and HEAD.
    Git { repo: PathBuf },
    /// Scan added lines between two commits in a local repository.
    GitRange { repo: PathBuf, #[arg(long)] base: String, #[arg(long)] head: String,
        #[arg(long, value_enum, default_value = "jsonl")] format: RangeFormat },
    /// Scan changed files from the Git index.
    Staged { repo: PathBuf },
    /// Print the number of compiled detectors.
    Rules { #[arg(long)] list: bool },
    /// HMAC the exact bytes of an owner-managed value received on stdin.
    Fingerprint,
}

#[derive(Serialize)]
pub struct Location<'a> {
    source: &'a str,
    path: &'a str,
    revision: Option<&'a str>,
    blob: Option<&'a str>,
}

pub struct Audit<W> {
    engine: Scanner,
    key: Option<evidence::Key>,
    inventory: evidence::Inventory,
    verified_only: bool,
    now: u64,
    max_age: u64,
    limit: u64,
    out: W,
    sarif: Option<sarif::Writer>,
    baseline_writer: Option<(PathBuf, baseline::Writer)>,
    baseline_filter: Option<baseline::Filter>,
    baselined: u64,
    documents: u64,
    candidates: u64,
    emitted: u64,
    incomplete: u64,
}

fn overlaps_added_lines(
    bytes: &[u8],
    secret_start_offset: usize,
    secret: &[u8],
    added: &[RangeInclusive<usize>],
) -> bool {
    let first_line = 1 + bytes[..secret_start_offset].iter().filter(|&&byte| byte == b'\n').count();
    let covered_lines = secret.iter().filter(|&&byte| byte == b'\n').count();
    let trailing_newline = usize::from(secret.last() == Some(&b'\n'));
    let last_line = first_line + covered_lines.saturating_sub(trailing_newline);
    added.iter().any(|range| *range.start() <= last_line && *range.end() >= first_line)
}

impl<W: Write> Audit<W> {
    pub(crate) fn set_sarif_root(&mut self, path: &str) {
        if let Some(sarif) = &mut self.sarif { sarif.set_source_root(path); }
    }

    fn document(&mut self, loc: Location<'_>, bytes: &[u8]) -> Result<()> {
        self.document_selected(loc, bytes, None)
    }

    fn document_added_lines(&mut self, loc: Location<'_>, bytes: &[u8], added: &[RangeInclusive<usize>]) -> Result<()> {
        self.document_selected(loc, bytes, Some(added))
    }

    fn document_selected(&mut self, loc: Location<'_>, bytes: &[u8], added: Option<&[RangeInclusive<usize>]>) -> Result<()> {
        let scanned = self.engine.scan_bytes_detailed(loc.path, bytes);
        self.documents += 1;
        if scanned.findings_truncated {
            self.skip(&loc, "detector finding cap")?;
        }
        for hit in scanned.findings {
            let raw = bytes.get(hit.secret_start_offset..hit.secret_end_offset)
                .context("invalid detector offsets")?;
            if let Some(added) = added {
                if !overlaps_added_lines(bytes, hit.secret_start_offset, raw, added) {
                    continue;
                }
            }
            self.candidates += 1;
            if let Some((_, baseline)) = &mut self.baseline_writer {
                baseline.add(&hit.rule_id, loc.path, hit.line, hit.col)?;
                continue;
            }
            if let Some(baseline) = &self.baseline_filter {
                if baseline.contains(&hit.rule_id, loc.path, hit.line, hit.col)? {
                    self.baselined += 1;
                    continue;
                }
            }
            let digest = self.key.as_ref().filter(|_| !raw.is_empty())
                .map(|key| evidence::fingerprint(key, raw));
            let (status, record) = self.inventory.lookup(digest.as_deref(), self.now, self.max_age);
            if self.verified_only && status != "verified" { continue; }
            // Build a fresh report: the engine finding also contains source context.
            if let Some(sarif) = &mut self.sarif {
                let was_truncated = sarif.is_truncated();
                let accepted = sarif.add(&hit.rule_id, &hit.rule_description, loc.path,
                    hit.line, hit.col_utf16, loc.revision)?;
                if !accepted && !was_truncated { self.incomplete += 1; }
                self.emitted += u64::from(accepted);
            } else {
                let report = json!({
                    "location": loc, "line": hit.line, "column": hit.col, "detector": hit.rule_id,
                    "classification": hit.rule_description, "status": status, "fingerprint": digest,
                    "inventory": record,
                });
                serde_json::to_writer(&mut self.out, &report)?;
                writeln!(self.out)?;
                self.emitted += 1;
            }
        }
        Ok(())
    }

    fn skip(&mut self, loc: &Location<'_>, reason: &str) -> Result<()> {
        self.incomplete += 1;
        writeln!(io::stderr().lock(), "{}", json!({"skipped": loc, "reason": reason}))?;
        Ok(())
    }
}

const MAX_RULES_FILE_BYTES: u64 = 8 * 1024 * 1024;

fn read_rules_file(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("checking custom rules file {:?}", path))?;
    ensure!(metadata.is_file(), "--rules must refer to a regular file");
    let mut reader = std::fs::File::open(path)
        .with_context(|| format!("opening custom rules file {:?}", path))?
        .take(MAX_RULES_FILE_BYTES + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading custom rules file {:?}", path))?;
    ensure!(
        bytes.len() <= MAX_RULES_FILE_BYTES as usize,
        "custom rules file exceeds 8 MiB"
    );
    String::from_utf8(bytes).context("custom rules file must be UTF-8")
}

fn preflight_failure<T>(error: anyhow::Error, sarif_output: bool) -> Result<T> {
    if sarif_output {
        let mut out = BufWriter::new(io::stdout().lock());
        sarif::Writer::default().write(&mut out, false)?;
        out.flush()?;
    }
    Err(error)
}

fn run() -> Result<u8> {
    let cli = Cli::parse();
    let sarif_output = matches!(&cli.command,
        Source::GitRange { format: RangeFormat::Sarif, .. });
    if (cli.write_baseline.is_some() || cli.baseline.is_some())
        && matches!(cli.command, Source::Fingerprint | Source::Rules { .. })
    {
        return preflight_failure(anyhow::anyhow!("baseline options require a scan source"), sarif_output);
    }
    if cli.rules.is_some() && matches!(cli.command, Source::Fingerprint) {
        return preflight_failure(anyhow::anyhow!("--rules requires a scan or rules command"), sarif_output);
    }
    if matches!(cli.command, Source::Fingerprint) {
        let key = evidence::key()?.context("set BASSET_HMAC_KEY to fingerprint a value")?;
        let bytes = inputs::bounded(io::stdin().lock(), cli.max_bytes)?
            .context("input exceeds --max-bytes")?;
        ensure!(!bytes.is_empty(), "empty fingerprint input");
        println!("{}", evidence::fingerprint(&key, &bytes));
        return Ok(0);
    }
    let baseline_filter = match cli.baseline.as_deref().map(baseline::Filter::load).transpose() {
        Ok(filter) => filter,
        Err(error) => return preflight_failure(error, sarif_output),
    };
    let scanner = match cli.rules.as_deref() {
        Some(path) => {
            let custom_rules = match read_rules_file(path) {
                Ok(rules) => rules,
                Err(error) => return preflight_failure(error, sarif_output),
            };
            match Scanner::from_bundled_with_rules(&custom_rules) {
                Ok(scanner) => scanner,
                Err(error) => {
                    return preflight_failure(
                        anyhow::Error::new(error).context("invalid custom rules"),
                        sarif_output,
                    );
                }
            }
        }
        None => match Scanner::from_bundled() {
            Ok(scanner) => scanner,
            Err(_) => return preflight_failure(anyhow::anyhow!("could not compile bundled detector rules"), sarif_output),
        },
    };
    let engine = scanner.with_config(ScanConfig {
        honor_allow_markers: false,
        ..ScanConfig::default()
    });
    let count = engine.engine().rule_count();
    if count < 800 { return preflight_failure(anyhow::anyhow!("catalog contains only {count} compiled rules"), sarif_output); }
    if let Source::Rules { list } = &cli.command {
        if *list {
            let mut out = BufWriter::new(io::stdout().lock());
            for rule in engine.engine().rules() {
                writeln!(out, "{}", json!({"id":rule.id,"description":rule.description}))?;
            }
            out.flush()?;
            return Ok(0);
        }
        println!("{}", json!({"compiled_rules":count,"engine":"secrets_scanner/0.2.3"}));
        return Ok(0);
    }
    let baseline_path = cli.write_baseline.clone();
    let verified_only = cli.only_verified || cli.results == Filter::Verified;
    let key = match evidence::key() { Ok(key) => key, Err(error) => return preflight_failure(error, sarif_output) };
    if verified_only && cli.inventory.is_none() {
        return preflight_failure(anyhow::anyhow!("verified filtering requires --inventory"), sarif_output);
    }
    if cli.inventory.is_some() && key.is_none() {
        return preflight_failure(anyhow::anyhow!("--inventory requires BASSET_HMAC_KEY"), sarif_output);
    }
    let inventory = match cli.inventory.as_deref().map(evidence::Inventory::load).transpose() {
        Ok(inventory) => inventory.unwrap_or_default(),
        Err(error) => return preflight_failure(error, sarif_output),
    };
    let now = match evidence::now() { Ok(now) => now, Err(error) => return preflight_failure(error, sarif_output) };
    let mut audit = Audit {
        engine, key, inventory, verified_only, now, max_age: cli.max_age_seconds,
        limit: cli.max_bytes, out: BufWriter::new(io::stdout().lock()),
        sarif: sarif_output.then(sarif::Writer::default),
        baseline_writer: baseline_path.map(|path| (path, baseline::Writer::default())),
        baseline_filter, baselined: 0, documents: 0, candidates: 0, emitted: 0, incomplete: 0,
    };
    let result = match cli.command {
        Source::Fs { path } => inputs::files(&path, &mut audit),
        Source::Stdin { name } => inputs::stream(io::stdin().lock(),
            Location { source: "stdin", path: &name, revision: None, blob: None }, &mut audit),
        Source::Records => inputs::records(io::stdin().lock(), &mut audit),
        Source::Git { repo } => git::scan(&repo, false, &mut audit),
        Source::GitRange { repo, base, head, .. } => git::scan_range(&repo, &base, &head, &mut audit),
        Source::Staged { repo } => git::scan(&repo, true, &mut audit),
        _ => unreachable!("handled before scanning"),
    };
    if result.is_err() && audit.sarif.is_some() { audit.incomplete += 1; }
    if let Some(sarif) = audit.sarif.take() {
        sarif.write(&mut audit.out, audit.incomplete == 0)?;
    }
    audit.out.flush()?;
    result?;
    if let Some((path, baseline)) = audit.baseline_writer.take() {
        ensure!(audit.incomplete == 0, "cannot write a baseline from an incomplete scan");
        baseline.write(&path)?;
    }
    eprintln!("{}", json!({"documents":audit.documents, "candidates":audit.candidates,
        "baselined":audit.baselined,"reported":audit.emitted,"incomplete":audit.incomplete}));
    Ok(if audit.incomplete > 0 { 2 } else if audit.emitted > 0 { 1 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::overlaps_added_lines;

    #[test]
    fn range_filter_uses_secret_capture_start_line() {
        let bytes = b"match-prefix\nsecret\n";
        let secret_start = bytes.iter().position(|&byte| byte == b's').unwrap();
        assert!(overlaps_added_lines(bytes, secret_start, b"secret", &[2..=2]));
        assert!(!overlaps_added_lines(bytes, secret_start, b"secret", &[1..=1]));
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => { eprintln!("basset: {error:#}"); ExitCode::from(2) }
    }
}
