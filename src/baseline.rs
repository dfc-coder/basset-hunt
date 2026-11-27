use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Write};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const MAX_BASELINE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_BASELINE_ENTRIES: usize = 100_000;

#[derive(Default)]
pub(crate) struct Writer {
    entries: BTreeSet<Entry>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct Entry {
    rule: String,
    location_fingerprint: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    entries: Vec<Entry>,
}

pub(crate) struct Filter {
    entries: BTreeSet<Entry>,
}

fn location_fingerprint(rule: &str, path: &str, line: usize, column: usize) -> Result<String> {
    let fingerprint = super::sarif::location_fingerprint(rule, path, line, column)?;
    let digest = fingerprint
        .strip_prefix("sha256:")
        .context("invalid internal location fingerprint")?;
    let mut grouped = String::with_capacity(fingerprint.len() + 15);
    grouped.push_str("sha256:");
    for (index, group) in digest.as_bytes().chunks(4).enumerate() {
        if index > 0 {
            grouped.push('-');
        }
        for byte in group {
            grouped.push(char::from(*byte));
        }
    }
    Ok(grouped)
}

impl Filter {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("opening baseline {}", path.display()))?;
        ensure!(
            file.metadata()?.len() <= MAX_BASELINE_BYTES,
            "baseline exceeds 32 MiB"
        );
        let document: Document =
            serde_json::from_reader(BufReader::new(file)).context("parsing baseline JSON")?;
        ensure!(document.version == 1, "unsupported baseline version");
        ensure!(
            document.entries.len() <= MAX_BASELINE_ENTRIES,
            "baseline has too many entries"
        );
        for entry in &document.entries {
            ensure!(
                !entry.rule.is_empty()
                    && entry.rule.len() <= 256
                    && entry
                        .rule
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "invalid rule identifier in baseline"
            );
            let fingerprint = entry
                .location_fingerprint
                .strip_prefix("sha256:")
                .context("invalid location fingerprint in baseline")?;
            let groups: Vec<_> = fingerprint.split('-').collect();
            ensure!(
                groups.len() == 16
                    && groups.iter().all(|group| {
                        group.len() == 4
                            && group
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    }),
                "invalid location fingerprint in baseline"
            );
        }
        let count = document.entries.len();
        let entries: BTreeSet<_> = document.entries.into_iter().collect();
        ensure!(entries.len() == count, "duplicate entry in baseline");
        Ok(Self { entries })
    }

    pub(crate) fn contains(
        &self,
        rule: &str,
        path: &str,
        line: usize,
        column: usize,
    ) -> Result<bool> {
        let entry = Entry {
            rule: rule.to_owned(),
            location_fingerprint: location_fingerprint(rule, path, line, column)?,
        };
        Ok(self.entries.contains(&entry))
    }
}

impl Writer {
    pub(crate) fn add(&mut self, rule: &str, path: &str, line: usize, column: usize) -> Result<()> {
        self.entries.insert(Entry {
            rule: rule.to_owned(),
            location_fingerprint: location_fingerprint(rule, path, line, column)?,
        });
        Ok(())
    }

    pub(crate) fn write(self, path: &Path) -> Result<()> {
        let document = Document {
            version: 1,
            entries: self.entries.into_iter().collect(),
        };
        let bytes = serde_json::to_vec_pretty(&document)?;
        write_atomically(path, &bytes)
    }
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = path.file_name().context("baseline path must name a file")?;
    let mut temp_name = OsString::from(".");
    temp_name.push(file_name);
    temp_name.push(format!(".{}.tmp", std::process::id()));
    let temp_path = parent.join(temp_name);
    let mut temp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .with_context(|| format!("creating temporary baseline in {}", parent.display()))?;

    let result = temp_file
        .write_all(bytes)
        .and_then(|()| temp_file.sync_all());
    drop(temp_file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temp_path);
        return Err(error).context("writing temporary baseline");
    }
    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(error).context("replacing baseline file");
    }
    Ok(())
}
