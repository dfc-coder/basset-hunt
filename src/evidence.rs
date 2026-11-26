use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub type Key = Hmac<Sha256>;

pub fn key() -> Result<Option<Key>> {
    let configured_key = env::var("BASSET_HMAC_KEY").or_else(|error| match error {
        env::VarError::NotPresent => env::var("CREDCHECK_HMAC_KEY"),
        other => Err(other),
    });
    let value = match configured_key {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(None),
        Err(_) => bail!("BASSET_HMAC_KEY must be hexadecimal"),
    };
    let bytes = hex::decode(value).context("BASSET_HMAC_KEY must be hexadecimal")?;
    ensure!(bytes.len() == 32, "BASSET_HMAC_KEY must encode 32 bytes");
    Ok(Some(Key::new_from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid key"))?))
}

pub fn fingerprint(key: &Key, bytes: &[u8]) -> String {
    let mut mac = key.clone();
    mac.update(bytes);
    hex::encode(mac.finalize().into_bytes())
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum State { Active, Inactive, Revoked }

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub fingerprint: String,
    pub state: State,
    pub checked_at: u64,
    pub owner: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    pub rotation_runbook: Option<String>,
}

#[derive(Default)]
pub struct Inventory(HashMap<String, Record>);

impl Inventory {
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path).context("opening trusted inventory")?;
        ensure!(file.metadata()?.len() <= 32 * 1024 * 1024, "inventory exceeds 32 MiB");
        let rows: Vec<Record> = serde_json::from_reader(BufReader::new(file))
            .map_err(|e| anyhow::anyhow!("invalid inventory at line {}, column {}", e.line(), e.column()))?;
        let mut records = HashMap::new();
        for row in rows {
            ensure!(row.fingerprint.len() == 64 && row.fingerprint.bytes().all(|b|
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "invalid inventory fingerprint");
            ensure!(!row.owner.trim().is_empty(), "missing inventory owner");
            ensure!(records.insert(row.fingerprint.clone(), row).is_none(), "duplicate inventory fingerprint");
        }
        Ok(Self(records))
    }

    pub fn lookup(&self, digest: Option<&str>, now: u64, max_age: u64) -> (&'static str, Option<&Record>) {
        let Some(row) = digest.and_then(|id| self.0.get(id)) else { return ("unknown", None) };
        let state = match now.checked_sub(row.checked_at) {
            Some(age) if age <= max_age => match row.state {
                State::Active => "verified",
                State::Inactive => "inactive",
                State::Revoked => "revoked",
            },
            _ => "stale",
        };
        (state, Some(row))
    }
}

pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freshness_has_inclusive_boundaries() {
        let mut inventory = Inventory::default();
        let id = "a".repeat(64);
        inventory.0.insert(id.clone(), Record {
            fingerprint: id.clone(), state: State::Active, checked_at: 100, owner: "platform".into(),
            permissions: Vec::new(), rotation_runbook: None,
        });
        assert_eq!(inventory.lookup(Some(&id), 99, 10).0, "stale");
        assert_eq!(inventory.lookup(Some(&id), 100, 10).0, "verified");
        assert_eq!(inventory.lookup(Some(&id), 110, 10).0, "verified");
        assert_eq!(inventory.lookup(Some(&id), 111, 10).0, "stale");
        assert_eq!(inventory.lookup(None, 100, 10).0, "unknown");
    }

    #[test]
    fn fingerprints_match_rfc4231_vector() -> Result<()> {
        let key = Key::new_from_slice(&[0x0b; 20]).map_err(|_| anyhow::anyhow!("invalid test key"))?;
        assert_eq!(fingerprint(&key, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        Ok(())
    }
}
