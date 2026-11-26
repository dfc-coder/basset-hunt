use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use walkdir::WalkDir;

use crate::{Audit, Location};

pub fn bounded(input: impl Read, limit: u64) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    input.take(limit + 1).read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= limit).then_some(bytes))
}

pub fn stream<W: Write>(input: impl Read, loc: Location<'_>, audit: &mut Audit<W>) -> Result<()> {
    match bounded(input, audit.limit)? {
        Some(bytes) => audit.document(loc, &bytes),
        None => audit.skip(&loc, "document exceeds --max-bytes"),
    }
}

pub fn files<W: Write>(root: &Path, audit: &mut Audit<W>) -> Result<()> {
    let metadata = root.symlink_metadata()?;
    ensure!(metadata.is_dir() || metadata.is_file(), "input must be a regular file or directory");
    let walker = WalkDir::new(root).follow_links(false).follow_root_links(false)
        .into_iter().filter_entry(|e| e.file_name() != ".git");
    for entry in walker {
        let entry = entry.context("walking input directory")?;
        if !entry.file_type().is_file() { continue; }
        let path = entry.path().to_str().context("input path is not UTF-8")?;
        let loc = Location { source: "filesystem", path, revision: None, blob: None };
        if entry.metadata()?.len() > audit.limit {
            audit.skip(&loc, "file exceeds --max-bytes")?;
        } else {
            stream(File::open(entry.path()).context("opening input file")?, loc, audit)?;
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    source: String,
    path: String,
    revision: Option<String>,
    content: String,
}

pub fn records<W: Write>(mut input: impl BufRead, audit: &mut Audit<W>) -> Result<()> {
    let mut number = 0u64;
    // A JSON escape can represent one content byte with six wire bytes.
    let wire_limit = 6 * audit.limit + 65536;
    let mut line = Vec::new();
    loop {
        line.clear();
        if (&mut input).take(wire_limit + 1).read_until(b'\n', &mut line)? == 0 { break; }
        number += 1;
        ensure!(line.len() as u64 <= wire_limit, "export record {number} exceeds wire limit");
        let doc: Document = serde_json::from_slice(&line)
            .map_err(|_| anyhow::anyhow!("invalid export record {number}"))?;
        ensure!(!doc.source.is_empty() && !doc.path.is_empty(), "missing location at record {number}");
        let loc = Location { source: &doc.source, path: &doc.path, revision: doc.revision.as_deref(), blob: None };
        if doc.content.len() as u64 > audit.limit { audit.skip(&loc, "record exceeds --max-bytes")?; }
        else { audit.document(loc, doc.content.as_bytes())?; }
    }
    Ok(())
}
