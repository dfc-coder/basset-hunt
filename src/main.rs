mod evidence;
mod git;
mod inputs;

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use secrets_scanner::Scanner;
use serde::Serialize;
use serde_json::json;

#[derive(Parser)]
#[command(name = "basset", version, about = "Scan local content and correlate findings with trusted credential inventory")]
struct Cli {
    #[command(subcommand)]
    command: Source,
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
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Filter { All, Verified }

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
    documents: u64,
    candidates: u64,
    emitted: u64,
    incomplete: u64,
}

impl<W: Write> Audit<W> {
    fn document(&mut self, loc: Location<'_>, bytes: &[u8]) -> Result<()> {
        let scanned = self.engine.scan_bytes_detailed(loc.path, bytes);
        self.documents += 1;
        if scanned.findings_truncated {
            self.skip(&loc, "detector finding cap")?;
        }
        for hit in scanned.findings {
            self.candidates += 1;
            let raw = bytes.get(hit.secret_start_offset..hit.secret_end_offset)
                .context("invalid detector offsets")?;
            let digest = self.key.as_ref().filter(|_| !raw.is_empty())
                .map(|key| evidence::fingerprint(key, raw));
            let (status, record) = self.inventory.lookup(digest.as_deref(), self.now, self.max_age);
            if self.verified_only && status != "verified" { continue; }
            // Build a fresh report: the engine finding also contains source context.
            let report = json!({
                "location": loc, "line": hit.line, "column": hit.col, "detector": hit.rule_id,
                "classification": hit.rule_description, "status": status, "fingerprint": digest,
                "inventory": record,
            });
            serde_json::to_writer(&mut self.out, &report)?;
            writeln!(self.out)?;
            self.emitted += 1;
        }
        Ok(())
    }

    fn skip(&mut self, loc: &Location<'_>, reason: &str) -> Result<()> {
        self.incomplete += 1;
        writeln!(io::stderr().lock(), "{}", json!({"skipped": loc, "reason": reason}))?;
        Ok(())
    }
}

fn run() -> Result<u8> {
    let cli = Cli::parse();
    if matches!(cli.command, Source::Fingerprint) {
        let key = evidence::key()?.context("set BASSET_HMAC_KEY to fingerprint a value")?;
        let bytes = inputs::bounded(io::stdin().lock(), cli.max_bytes)?
            .context("input exceeds --max-bytes")?;
        ensure!(!bytes.is_empty(), "empty fingerprint input");
        println!("{}", evidence::fingerprint(&key, &bytes));
        return Ok(0);
    }
    let engine = Scanner::from_bundled().map_err(|_| anyhow::anyhow!("could not compile bundled detector rules"))?;
    let count = engine.engine().rule_count();
    ensure!(count >= 800, "catalog contains only {count} compiled rules");
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
    let verified_only = cli.only_verified || cli.results == Filter::Verified;
    let key = evidence::key()?;
    ensure!(!verified_only || cli.inventory.is_some(), "verified filtering requires --inventory");
    ensure!(cli.inventory.is_none() || key.is_some(), "--inventory requires BASSET_HMAC_KEY");
    let inventory = cli.inventory.as_deref().map(evidence::Inventory::load).transpose()?.unwrap_or_default();
    let mut audit = Audit {
        engine, key, inventory, verified_only, now: evidence::now()?, max_age: cli.max_age_seconds,
        limit: cli.max_bytes, out: BufWriter::new(io::stdout().lock()), documents: 0,
        candidates: 0, emitted: 0, incomplete: 0,
    };
    let result = match cli.command {
        Source::Fs { path } => inputs::files(&path, &mut audit),
        Source::Stdin { name } => inputs::stream(io::stdin().lock(),
            Location { source: "stdin", path: &name, revision: None, blob: None }, &mut audit),
        Source::Records => inputs::records(io::stdin().lock(), &mut audit),
        Source::Git { repo } => git::scan(&repo, false, &mut audit),
        Source::Staged { repo } => git::scan(&repo, true, &mut audit),
        _ => unreachable!("handled before scanning"),
    };
    audit.out.flush()?;
    result?;
    eprintln!("{}", json!({"documents":audit.documents, "candidates":audit.candidates,
        "reported":audit.emitted,"incomplete":audit.incomplete}));
    Ok(if audit.incomplete > 0 { 2 } else if audit.emitted > 0 { 1 } else { 0 })
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => { eprintln!("basset: {error:#}"); ExitCode::from(2) }
    }
}
