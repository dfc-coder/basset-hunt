use std::collections::BTreeMap;
use std::io::{self, Write};

use anyhow::Result;
use crate::FindingMetadata;
use serde_json::json;
use sha2::{Digest, Sha256};

const MAX_RESULTS: usize = 1_000;
const SRCROOT: &str = "%SRCROOT%";

pub(crate) struct FindingLocation<'a> {
    pub(crate) path: &'a str,
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) commit: Option<&'a str>,
}

pub(crate) struct Writer {
    rules: BTreeMap<String, String>,
    results: Vec<serde_json::Value>,
    source_root: Option<String>,
    limit: usize,
    truncated: bool,
}

impl Default for Writer {
    fn default() -> Self {
        Self::with_limit(MAX_RESULTS)
    }
}

impl Writer {
    fn with_limit(limit: usize) -> Self {
        Self {
            rules: BTreeMap::new(),
            results: Vec::new(),
            source_root: None,
            limit,
            truncated: false,
        }
    }

    pub(crate) fn set_source_root(&mut self, path: &str) {
        self.source_root = Some(file_uri_root(path));
    }

    pub(crate) fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn add(
        &mut self,
        rule_id: &str,
        description: &str,
        location: FindingLocation<'_>,
        metadata: &FindingMetadata,
    ) -> Result<bool> {
        if self.results.len() >= self.limit {
            self.truncated = true;
            return Ok(false);
        }

        let fingerprint = location_fingerprint(
            rule_id, location.path, location.line, location.column,
        )?;
        self.rules
            .entry(rule_id.to_owned())
            .or_insert_with(|| description.to_owned());
        let mut properties = json!({ "commit": location.commit });
        if let Some(encoding) = metadata.encoding.as_deref() {
            properties["encoding"] = json!(encoding);
        }
        if let Some(archive_entry) = metadata.archive_entry.as_deref() {
            properties["archive_entry"] = json!(archive_entry);
        }
        self.results.push(json!({
            "ruleId": rule_id,
            "level": "warning",
            "message": { "text": "Potential secret detected." },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": uri_path(location.path, false), "uriBaseId": SRCROOT },
                    "region": { "startLine": location.line.max(1), "startColumn": location.column.max(1) }
                }
            }],
            "partialFingerprints": { "primaryLocationLineHash": fingerprint },
            "properties": properties
        }));
        Ok(true)
    }

    pub(crate) fn write(
        &self,
        output: &mut impl Write,
        execution_successful: bool,
    ) -> io::Result<()> {
        let rules = self
            .rules
            .iter()
            .map(|(id, description)| {
                json!({
                    "id": id,
                    "name": id,
                    "shortDescription": { "text": description }
                })
            })
            .collect::<Vec<_>>();
        let root = self.source_root.as_deref().unwrap_or("file:///");
        let document = json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "Basset", "version": env!("CARGO_PKG_VERSION"), "rules": rules } },
                "originalUriBaseIds": { SRCROOT: { "uri": root } },
                "results": self.results,
                "invocations": [{ "executionSuccessful": execution_successful }]
            }]
        });
        serde_json::to_writer(&mut *output, &document)?;
        writeln!(output)
    }
}

pub(crate) fn location_fingerprint(
    rule_id: &str,
    path: &str,
    line: usize,
    column: usize,
) -> Result<String> {
    let identity = serde_json::to_vec(&("basset/v1", rule_id, path, line, column))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(identity))))
}

fn uri_path(path: &str, keep_drive_colon: bool) -> String {
    let bytes = path.as_bytes();
    let drive_colon = keep_drive_colon
        && path.starts_with('/')
        && bytes.get(2) == Some(&b':')
        && bytes.get(3) == Some(&b'/');
    let mut uri = String::with_capacity(path.len());
    for (index, &byte) in bytes.iter().enumerate() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/')
            || (drive_colon && index == 2)
        {
            uri.push(char::from(byte));
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri
}

fn file_uri_root(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let rooted = if normalized.starts_with('/') {
        normalized
    } else {
        format!("/{normalized}")
    };
    let mut uri = format!("file://{}", uri_path(&rooted, true));
    if !uri.ends_with('/') {
        uri.push('/');
    }
    uri
}

#[cfg(test)]
mod tests {
    use super::{FindingLocation, Writer};
    use serde_json::Value;

    #[test]
    fn sarif_uses_relative_uris_generic_messages_and_location_identity() {
        let mut writer = Writer::default();
        writer.set_source_root("/tmp/basset repo");
        writer
            .add(
                "private-key",
                "Private key",
                FindingLocation { path: "a b/key#1.pem", line: 3, column: 2, commit: Some("abc123") },
                &crate::FindingMetadata::default(),
            )
            .unwrap();
        let mut output = Vec::new();
        writer.write(&mut output, true).unwrap();
        let text = String::from_utf8(output).unwrap();
        let document: Value = serde_json::from_str(&text).unwrap();
        let run = &document["runs"][0];
        let result = &run["results"][0];
        assert_eq!(document["version"], "2.1.0");
        assert_eq!(run["invocations"][0]["executionSuccessful"], true);
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "a%20b/key%231.pem"
        );
        assert_eq!(result["message"]["text"], "Potential secret detected.");
        assert_eq!(result["properties"]["commit"], "abc123");
        assert!(result["properties"].get("encoding").is_none());
        assert!(result["properties"].get("archive_entry").is_none());
        assert_eq!(
            run["originalUriBaseIds"]["%SRCROOT%"]["uri"],
            "file:///tmp/basset%20repo/"
        );
        assert_eq!(super::uri_path("a:b.txt", false), "a%3Ab.txt");
        assert_eq!(super::file_uri_root("/C:/repo"), "file:///C:/repo/");

        let mut repeat = Writer::default();
        repeat
            .add(
                "private-key",
                "Private key",
                FindingLocation { path: "a b/key#1.pem", line: 3, column: 2, commit: Some("different-commit") },
                &crate::FindingMetadata::default(),
            )
            .unwrap();
        assert_eq!(
            repeat.results[0]["partialFingerprints"],
            result["partialFingerprints"]
        );
    }

    #[test]
    fn optional_finding_metadata_is_serialized_in_sarif_properties() {
        let metadata = crate::FindingMetadata {
            encoding: Some("base64".to_owned()),
            archive_entry: Some("archive.zip:entry.txt".to_owned()),
        };
        let mut writer = Writer::default();
        writer.add(
            "rule", "Rule",
            FindingLocation { path: "input", line: 1, column: 1, commit: None },
            &metadata,
        ).expect("add finding");
        let mut output = Vec::new();
        writer.write(&mut output, true).expect("write SARIF");
        let document: Value = serde_json::from_slice(&output).expect("parse SARIF");
        let properties = &document["runs"][0]["results"][0]["properties"];
        assert_eq!(properties["encoding"], "base64");
        assert_eq!(properties["archive_entry"], "archive.zip:entry.txt");
    }

    #[test]
    fn reaching_result_limit_marks_invocation_incomplete_and_keeps_prior_results() {
        let mut writer = Writer::with_limit(1);
        assert!(writer.add("rule", "Rule",
            FindingLocation { path: "a.txt", line: 1, column: 1, commit: None },
            &crate::FindingMetadata::default()).unwrap());
        assert!(!writer.add("rule", "Rule",
            FindingLocation { path: "b.txt", line: 1, column: 1, commit: None },
            &crate::FindingMetadata::default()).unwrap());
        assert!(writer.is_truncated());
        let mut output = Vec::new();
        writer.write(&mut output, false).unwrap();
        let document: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(document["runs"][0]["results"].as_array().unwrap().len(), 1);
        assert_eq!(
            document["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
    }
}
