use std::collections::{HashMap, HashSet};
use std::fs::{create_dir_all, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::verify::VerifyInput;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Accept,
    RejectReplay,
    RejectInvalid,
}

pub trait NonceLedger: Send + Sync {
    fn check_and_record(&self, key: VerifyInput, now_ts: u64) -> Decision;
}

#[derive(Clone, Default)]
pub struct InMemoryNonceLedger {
    inner: Arc<Mutex<HashSet<VerifyInput>>>,
}

impl NonceLedger for InMemoryNonceLedger {
    fn check_and_record(&self, key: VerifyInput, _now_ts: u64) -> Decision {
        let mut guard = self.inner.lock().unwrap();
        if guard.contains(&key) || key.nonce == 0 {
            Decision::RejectReplay
        } else {
            guard.insert(key);
            Decision::Accept
        }
    }
}

#[derive(Clone)]
pub struct FileBackedNonceLedger {
    ttl_secs: u64,
    inner: Arc<Mutex<LedgerState>>,
}

struct LedgerState {
    index: HashMap<VerifyInput, u64>,
    file: std::fs::File,
}

impl FileBackedNonceLedger {
    pub fn open(path: PathBuf, ttl_secs: u64, now_ts: u64) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;

        let mut ledger = LedgerState {
            index: HashMap::new(),
            file,
        };
        // rebuild index
        let reader = BufReader::new(OpenOptions::new().read(true).open(&path)?);
        for line in reader.lines().map_while(Result::ok) {
            let parts: Vec<_> = line.split(' ').collect();
            if parts.len() != 9 {
                continue;
            }
            if let (
                Ok(ts),
                hl_key_id,
                canon_hash,
                run_id,
                Ok(retry_epoch),
                Ok(nonce_val),
                action,
                proposal_id,
                decision,
            ) = (
                parts[0].parse::<u64>(),
                parts[1].to_string(),
                parts[2].to_string(),
                parts[3].to_string(),
                parts[4].parse::<u64>(),
                parts[5].parse::<u64>(),
                parts[6].to_string(),
                parts[7].to_string(),
                parts[8].to_string(),
            ) {
                if now_ts.saturating_sub(ts) > ttl_secs {
                    continue;
                }
                let key = VerifyInput {
                    canon_hash,
                    run_id,
                    retry_epoch,
                    nonce: nonce_val,
                    action,
                    proposal_id,
                    hl_key_id,
                };
                if decision == "ACCEPT" {
                    ledger.index.insert(key, ts);
                }
            }
        }

        Ok(Self {
            ttl_secs,
            inner: Arc::new(Mutex::new(ledger)),
        })
    }

    fn append(
        &self,
        state: &mut LedgerState,
        ts: u64,
        key: &VerifyInput,
        decision: Decision,
    ) -> anyhow::Result<()> {
        let decision_str = match decision {
            Decision::Accept => "ACCEPT",
            Decision::RejectReplay => "REJECT_REPLAY",
            Decision::RejectInvalid => "REJECT_INVALID",
        };
        writeln!(
            state.file,
            "{ts} {} {} {} {} {} {} {} {decision_str}",
            key.hl_key_id,
            key.canon_hash,
            key.run_id,
            key.retry_epoch,
            key.nonce,
            key.action,
            key.proposal_id
        )?;
        state.file.flush()?;
        Ok(())
    }
}

impl NonceLedger for FileBackedNonceLedger {
    fn check_and_record(&self, key: VerifyInput, now_ts: u64) -> Decision {
        let mut guard = self.inner.lock().unwrap();
        // prune expired
        if self.ttl_secs > 0 {
            guard
                .index
                .retain(|_, ts| now_ts.saturating_sub(*ts) <= self.ttl_secs);
        }
        if key.nonce == 0 {
            let _ = self.append(&mut guard, now_ts, &key, Decision::RejectInvalid);
            return Decision::RejectInvalid;
        }
        if guard.index.contains_key(&key) {
            let _ = self.append(&mut guard, now_ts, &key, Decision::RejectReplay);
            return Decision::RejectReplay;
        }
        guard.index.insert(key.clone(), now_ts);
        let _ = self.append(&mut guard, now_ts, &key, Decision::Accept);
        Decision::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn key(nonce: u64) -> VerifyInput {
        VerifyInput {
            canon_hash: "c".into(),
            run_id: "r".into(),
            retry_epoch: 0,
            nonce,
            action: "a".into(),
            proposal_id: "p".into(),
            hl_key_id: "hl".into(),
        }
    }

    #[test]
    fn accepts_then_rejects_replay() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let ledger = FileBackedNonceLedger::open(path, 100, 10).unwrap();
        assert!(matches!(
            ledger.check_and_record(key(1), 11),
            Decision::Accept
        ));
        assert!(matches!(
            ledger.check_and_record(key(1), 12),
            Decision::RejectReplay
        ));
    }

    #[test]
    fn allows_after_ttl_expiry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let ledger = FileBackedNonceLedger::open(path, 5, 10).unwrap();
        assert!(matches!(
            ledger.check_and_record(key(2), 10),
            Decision::Accept
        ));
        assert!(matches!(
            ledger.check_and_record(key(2), 12),
            Decision::RejectReplay
        ));
        assert!(matches!(
            ledger.check_and_record(key(2), 17),
            Decision::Accept
        ));
    }

    #[test]
    fn rebuilds_index_from_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let ledger = FileBackedNonceLedger::open(path.clone(), 100, 1).unwrap();
        assert!(matches!(
            ledger.check_and_record(key(3), 2),
            Decision::Accept
        ));
        drop(ledger);
        let ledger = FileBackedNonceLedger::open(path, 100, 3).unwrap();
        assert!(matches!(
            ledger.check_and_record(key(3), 4),
            Decision::RejectReplay
        ));
    }

    #[test]
    fn logs_reject_invalid_nonce_zero() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let ledger = FileBackedNonceLedger::open(path.clone(), 100, 1).unwrap();
        assert!(matches!(
            ledger.check_and_record(key(0), 2),
            Decision::RejectInvalid
        ));
        let log = std::fs::read_to_string(path).unwrap();
        assert!(log.contains("REJECT_INVALID"));
    }
}
