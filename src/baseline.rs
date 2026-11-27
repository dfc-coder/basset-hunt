use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Default)]
pub(crate) struct Writer {
    entries: BTreeSet<Entry>,
}

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Entry {
    rule: String,
    location_fingerprint: String,
}

#[derive(Serialize)]
struct Document {
    version: u8,
    entries: Vec<Entry>,
}

impl Writer {
    pub(crate) fn add(&mut self, rule: &str, path: &str, line: usize, column: usize) -> Result<()> {
        self.entries.insert(Entry {
            rule: rule.to_owned(),
            location_fingerprint: super::sarif::location_fingerprint(rule, path, line, column)?,
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
