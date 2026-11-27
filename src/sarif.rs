use std::collections::BTreeMap;
use std::io::{self, Write};

use anyhow::Result;
use serde_json::json;
use sha2::{Digest, Sha256};

const MAX_RESULTS: usize = 1_000;
const SRCROOT: &str = "%SRCROOT%";

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
        path: &str,
        line: usize,
        column: usize,
        commit: Option<&str>,
    ) -> Result<bool> {
        if self.results.len() >= self.limit {
            self.truncated = true;
            return Ok(false);
        }

        let fingerprint = location_fingerprint(rule_id, path, line, column)?;
        self.rules
            .entry(rule_id.to_owned())
            .or_insert_with(|| description.to_owned());
        self.results.push(json!({
            "ruleId": rule_id,
            "level": "warning",
            "message": { "text": "Potential secret detected." },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": uri_path(path, false), "uriBaseId": SRCROOT },
                    "region": { "startLine": line.max(1), "startColumn": column.max(1) }
                }
            }],
            "partialFingerprints": { "primaryLocationLineHash": fingerprint },
            "properties": { "commit": commit }
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
    use super::Writer;
    use serde_json::Value;

    #[test]
    fn sarif_uses_relative_uris_generic_messages_and_location_identity() {
        let mut writer = Writer::default();
        writer.set_source_root("/tmp/basset repo");
        writer
            .add(
                "private-key",
                "Private key",
                "a b/key#1.pem",
                3,
                2,
                Some("abc123"),
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
                "a b/key#1.pem",
                3,
                2,
                Some("different-commit"),
            )
            .unwrap();
        assert_eq!(
            repeat.results[0]["partialFingerprints"],
            result["partialFingerprints"]
        );
    }

    #[test]
    fn reaching_result_limit_marks_invocation_incomplete_and_keeps_prior_results() {
        let mut writer = Writer::with_limit(1);
        assert!(writer.add("rule", "Rule", "a.txt", 1, 1, None).unwrap());
        assert!(!writer.add("rule", "Rule", "b.txt", 1, 1, None).unwrap());
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
