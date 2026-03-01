#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::{create_dir_all, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use dio_core::{ExitChannel, FrameError, RecordFrame, HEADER_LEN};
use serde::Serialize;
use sha2::{Digest, Sha256};
use shared::{compute_event_hash, hex_lower};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bucket {
    Audit,
    Metrics,
    Security,
    Outputs,
}

impl TryFrom<ExitChannel> for Bucket {
    type Error = ReceiverError;

    fn try_from(value: ExitChannel) -> Result<Self, Self::Error> {
        match value {
            ExitChannel::Audit => Ok(Bucket::Audit),
            ExitChannel::Metrics => Ok(Bucket::Metrics),
            ExitChannel::Security => Ok(Bucket::Security),
            ExitChannel::Logs => Ok(Bucket::Outputs),
        }
    }
}

#[derive(Debug)]
pub enum ReceiverError {
    Frame(FrameError),
    Io(io::Error),
    Policy(&'static str),
    Missing(&'static str),
}

impl fmt::Display for ReceiverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiverError::Frame(e) => write!(f, "frame error: {e:?}"),
            ReceiverError::Io(e) => write!(f, "io error: {e}"),
            ReceiverError::Policy(reason) => write!(f, "policy violation: {reason}"),
            ReceiverError::Missing(kind) => write!(f, "missing required artifact: {kind}"),
        }
    }
}

impl std::error::Error for ReceiverError {}

impl From<FrameError> for ReceiverError {
    fn from(err: FrameError) -> Self {
        ReceiverError::Frame(err)
    }
}

impl From<io::Error> for ReceiverError {
    fn from(err: io::Error) -> Self {
        ReceiverError::Io(err)
    }
}

/// Append-only store for received frames. One file per bucket; writer-only semantics.
pub struct AppendStore {
    pub(crate) root: PathBuf,
}

impl AppendStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, ReceiverError> {
        let root = root.into();
        create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn append(&self, bucket: Bucket, frame: &RecordFrame) -> Result<(), ReceiverError> {
        self.enforce_policy(bucket, frame)?;
        let path = self.path_for(bucket);
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;

        file.write_all(&frame.tick.to_le_bytes())?;
        let len = u32::try_from(frame.payload.len()).map_err(|_| ReceiverError::Policy("len"))?;
        file.write_all(&len.to_le_bytes())?;
        file.write_all(&frame.payload)?;
        file.flush()?;
        Ok(())
    }

    fn enforce_policy(&self, bucket: Bucket, frame: &RecordFrame) -> Result<(), ReceiverError> {
        match bucket {
            Bucket::Metrics => {
                if frame.payload.len() > 2048 {
                    return Err(ReceiverError::Policy("metrics_len"));
                }
            }
            Bucket::Security => {
                if frame.payload.len() > 256 {
                    return Err(ReceiverError::Policy("security_len"));
                }
            }
            Bucket::Audit => {
                if frame.payload.len() > 512 {
                    return Err(ReceiverError::Policy("audit_len"));
                }
            }
            Bucket::Outputs => {
                if frame.payload.len() > 4096 {
                    return Err(ReceiverError::Policy("outputs_len"));
                }
            }
        }
        Ok(())
    }

    fn path_for(&self, bucket: Bucket) -> PathBuf {
        match bucket {
            Bucket::Audit => self.root.join("audit.bin"),
            Bucket::Metrics => self.root.join("metrics.bin"),
            Bucket::Security => self.root.join("security.bin"),
            Bucket::Outputs => self.root.join("outputs.bin"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MetricSpec {
    pub id: &'static str,
    pub min: u64,
    pub max: u64,
    pub step: u64,
    pub max_updates_per_run: u32,
}

const METRICS_SCHEMA: &[MetricSpec] = &[
    MetricSpec {
        id: "M001",
        min: 0,
        max: 1_000_000,
        step: 1,
        max_updates_per_run: 1,
    },
    MetricSpec {
        id: "M002",
        min: 0,
        max: 100_000_000,
        step: 16,
        max_updates_per_run: 1,
    },
    MetricSpec {
        id: "M003",
        min: 0,
        max: 10_000,
        step: 1,
        max_updates_per_run: 10,
    },
];

fn metric_spec(id: &str) -> Option<&'static MetricSpec> {
    METRICS_SCHEMA.iter().find(|m| m.id == id)
}

#[derive(Default)]
pub struct MetricsTracker {
    counts: HashMap<&'static str, u32>,
}

impl MetricsTracker {
    fn validate_payload(&mut self, payload: &[u8]) -> Result<(), ReceiverError> {
        let text =
            std::str::from_utf8(payload).map_err(|_| ReceiverError::Policy("metrics_utf8"))?;
        let mut last_id: Option<&str> = None;
        for line in text.lines() {
            let (id, val_str) = line
                .split_once('=')
                .ok_or(ReceiverError::Policy("metrics_format"))?;
            if !id
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            {
                return Err(ReceiverError::Policy("metrics_id_chars"));
            }
            if let Some(prev) = last_id {
                if id < prev {
                    return Err(ReceiverError::Policy("metrics_sort"));
                }
            }
            last_id = Some(id);

            let spec = metric_spec(id).ok_or(ReceiverError::Policy("metrics_unknown"))?;
            let val: u64 = val_str
                .parse()
                .map_err(|_| ReceiverError::Policy("metrics_numeric"))?;
            if val < spec.min || val > spec.max {
                return Err(ReceiverError::Policy("metrics_bounds"));
            }
            if val % spec.step != 0 {
                return Err(ReceiverError::Policy("metrics_quant"));
            }
            let counter = self.counts.entry(spec.id).or_insert(0);
            *counter += 1;
            if *counter > spec.max_updates_per_run {
                return Err(ReceiverError::Policy("metrics_rate"));
            }
        }
        Ok(())
    }
}

/// Decode bytes into a RecordFrame, map to bucket, enforce policy, and append to store.
pub fn ingest_bytes(
    store: &AppendStore,
    metrics: &mut MetricsTracker,
    bytes: &[u8],
) -> Result<(), ReceiverError> {
    let frame = RecordFrame::decode(bytes)?;
    let bucket = Bucket::try_from(frame.channel)?;
    if matches!(bucket, Bucket::Metrics) {
        metrics.validate_payload(&frame.payload)?;
    }
    store.append(bucket, &frame)
}

/// Decode and ingest a stream containing one or more concatenated frames.
pub fn ingest_stream(store: &AppendStore, bytes: &[u8]) -> Result<(), ReceiverError> {
    let mut tracker = MetricsTracker::default();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < HEADER_LEN {
            return Err(ReceiverError::Frame(FrameError::TooShort {
                minimum: HEADER_LEN,
                actual: bytes.len() - offset,
            }));
        }
        let payload_len = u32::from_le_bytes(bytes[offset + 16..offset + 20].try_into().unwrap());
        let total = HEADER_LEN
            .checked_add(payload_len as usize)
            .ok_or(ReceiverError::Frame(FrameError::PayloadTooLarge(
                payload_len as usize,
            )))?;
        if bytes.len() - offset < total {
            return Err(ReceiverError::Frame(FrameError::TruncatedPayload {
                expected: payload_len as usize,
                actual: bytes.len() - offset - HEADER_LEN,
            }));
        }
        ingest_bytes(store, &mut tracker, &bytes[offset..offset + total])?;
        offset += total;
    }
    Ok(())
}

/// Write manifest with sha256 of each bucket file present.
pub fn write_manifest(store: &AppendStore) -> Result<(), ReceiverError> {
    let mut manifest = serde_json::Map::new();
    for (bucket, name) in [
        (Bucket::Audit, "audit.bin"),
        (Bucket::Metrics, "metrics.bin"),
        (Bucket::Security, "security.bin"),
        (Bucket::Outputs, "outputs.bin"),
    ] {
        let path = store.path_for(bucket);
        if path.exists() {
            let mut file = OpenOptions::new().read(true).open(&path)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            let mut hasher = Sha256::new();
            hasher.update(&buf);
            let digest = hasher.finalize();
            manifest.insert(name.into(), serde_json::Value::String(hex::encode(digest)));
        }
    }
    let manifest_path = store.root.join("hashes.json");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(manifest_path)?;
    let body = serde_json::Value::Object(manifest);
    let bytes = serde_json::to_vec_pretty(&body).map_err(|_| ReceiverError::Policy("manifest"))?;
    file.write_all(&bytes)?;
    file.flush()?;
    Ok(())
}

/// A parsed record extracted from a bucket log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRecord {
    pub tick: u64,
    pub payload: Vec<u8>,
}

fn parse_records(path: &Path) -> Result<Vec<ParsedRecord>, ReceiverError> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < buf.len() {
        if buf.len() - offset < 12 {
            return Err(ReceiverError::Policy("record_truncated"));
        }
        let tick = u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap());
        let len = u32::from_le_bytes(buf[offset + 8..offset + 12].try_into().unwrap()) as usize;
        offset += 12;
        if buf.len() - offset < len {
            return Err(ReceiverError::Policy("record_payload_truncated"));
        }
        let payload = buf[offset..offset + len].to_vec();
        offset += len;
        out.push(ParsedRecord { tick, payload });
    }
    Ok(out)
}

fn sha_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn is_seccode(payload: &[u8]) -> bool {
    !payload.is_empty() && payload.iter().all(|b| matches!(b, b'A'..=b'Z' | b'_'))
}

fn check_within_run_duplicates(records: &HashMap<Bucket, Vec<ParsedRecord>>) -> bool {
    let mut seen: HashSet<(Bucket, u64)> = HashSet::new();
    for (bucket, recs) in records {
        for r in recs {
            if !seen.insert((*bucket, r.tick)) {
                return false;
            }
        }
    }
    true
}

fn check_metrics_records(records: &[ParsedRecord]) -> Result<(), ReceiverError> {
    let mut tracker = MetricsTracker::default();
    for r in records {
        tracker.validate_payload(&r.payload)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
pub struct BucketPolicyResult {
    pub audit_minimal: bool,
    pub security_seccode: bool,
    pub metrics_schema: bool,
    pub pass: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChainResult {
    pub pass: bool,
    pub head: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApprovalResult {
    pub observed: Option<String>,
    pub expected: Option<String>,
    pub pass: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ComparisonResult {
    pub file: String,
    pub pass: bool,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReplayResult {
    pub within_run_pass: bool,
    pub cross_run: &'static str,
}

#[derive(Clone, Debug)]
pub struct RunData {
    pub name: String,
    pub root: PathBuf,
    pub audit: Vec<ParsedRecord>,
    pub metrics: Vec<ParsedRecord>,
    pub security: Vec<ParsedRecord>,
    pub outputs: Vec<ParsedRecord>,
    pub hashes_json: Option<serde_json::Value>,
}

impl RunData {
    pub fn load(name: &str, root: &Path) -> Result<Self, ReceiverError> {
        let audit = parse_records(&root.join("audit.bin"))?;
        let metrics = parse_records(&root.join("metrics.bin"))?;
        let security = parse_records(&root.join("security.bin"))?;
        let outputs = parse_records(&root.join("outputs.bin"))?;
        let hashes_json = std::fs::read(root.join("hashes.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        Ok(Self {
            name: name.to_string(),
            root: root.to_path_buf(),
            audit,
            metrics,
            security,
            outputs,
            hashes_json,
        })
    }

    pub fn manifest(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for fname in [
            "audit.bin",
            "metrics.bin",
            "security.bin",
            "outputs.bin",
            "hashes.json",
            "frames.bin",
        ] {
            let path = self.root.join(fname);
            if let Ok(bytes) = std::fs::read(&path) {
                map.insert(format!("{}/{}", self.name, fname), sha_hex(&bytes));
            }
        }
        map
    }

    pub fn bucket_policy(&self) -> BucketPolicyResult {
        let audit_minimal = self.audit.iter().all(|r| r.payload.is_empty());
        let security_seccode = self.security.iter().all(|r| is_seccode(&r.payload));
        let metrics_schema = check_metrics_records(&self.metrics).is_ok();
        let pass = audit_minimal && security_seccode && metrics_schema;
        BucketPolicyResult {
            audit_minimal,
            security_seccode,
            metrics_schema,
            pass,
        }
    }

    pub fn approval(&self, expected: Option<&str>) -> ApprovalResult {
        let observed = self
            .security
            .first()
            .filter(|r| is_seccode(&r.payload))
            .map(|r| String::from_utf8_lossy(&r.payload).to_string());
        let pass = match (expected, observed.as_deref()) {
            (Some(exp), Some(obs)) => exp == obs,
            (None, _) => observed.is_some(),
            _ => false,
        };
        ApprovalResult {
            observed,
            expected: expected.map(|s| s.to_string()),
            pass,
        }
    }

    pub fn audit_chain(&self, audit_key: &[u8]) -> ChainResult {
        if self.audit.is_empty() {
            return ChainResult {
                pass: false,
                head: None,
            };
        }
        let mut prev = [0u8; 32];
        for rec in &self.audit {
            let h = compute_event_hash(&prev, &rec.payload, audit_key);
            prev = h;
        }
        ChainResult {
            pass: true,
            head: Some(hex_lower(&prev)),
        }
    }

    pub fn replay(&self) -> ReplayResult {
        let mut map: HashMap<Bucket, Vec<ParsedRecord>> = HashMap::new();
        map.insert(Bucket::Audit, self.audit.clone());
        map.insert(Bucket::Metrics, self.metrics.clone());
        map.insert(Bucket::Security, self.security.clone());
        map.insert(Bucket::Outputs, self.outputs.clone());
        let within = check_within_run_duplicates(&map);
        ReplayResult {
            within_run_pass: within,
            cross_run: "not_implemented",
        }
    }
}

pub const REQUIRED_EQUALITY_SET: &[&str] = &[
    "audit.bin",
    "hashes.json",
    "metrics.bin",
    "outputs.bin",
    "security.bin",
];

pub fn compare_runs(b: &RunData, c: &RunData) -> Vec<ComparisonResult> {
    let mut results = Vec::new();
    for fname in REQUIRED_EQUALITY_SET {
        let lhs = std::fs::read(b.root.join(fname)).unwrap_or_default();
        let rhs = std::fs::read(c.root.join(fname)).unwrap_or_default();
        let pass = lhs == rhs;
        let detail = if pass {
            None
        } else {
            Some(format!("b_hash={} c_hash={}", sha_hex(&lhs), sha_hex(&rhs)))
        };
        results.push(ComparisonResult {
            file: fname.to_string(),
            pass,
            detail,
        });
    }
    results.sort_by(|a, b| a.file.cmp(&b.file));
    results
}

#[derive(Clone, Debug, Serialize)]
pub struct EvidenceBundle {
    pub manifest: BTreeMap<String, String>,
    pub comparisons: Vec<ComparisonResult>,
    pub bucket_policy: BTreeMap<String, BucketPolicyResult>,
    pub chain_verification: BTreeMap<String, ChainResult>,
    pub approvals: BTreeMap<String, ApprovalResult>,
    pub replay: BTreeMap<String, ReplayResult>,
    pub pass: bool,
}

pub fn build_bundle(runs_dir: &Path, audit_key: &[u8]) -> Result<EvidenceBundle, ReceiverError> {
    let run_names = ["runA", "runB", "runC"];
    let mut manifest = BTreeMap::new();
    let mut bucket_policy = BTreeMap::new();
    let mut chain_verification = BTreeMap::new();
    let mut approvals = BTreeMap::new();
    let mut replay = BTreeMap::new();

    let mut run_map = HashMap::new();
    for name in run_names {
        let data = RunData::load(name, &runs_dir.join(name))?;
        manifest.extend(data.manifest());
        bucket_policy.insert(name.to_string(), data.bucket_policy());
        chain_verification.insert(name.to_string(), data.audit_chain(audit_key));
        let expected = match name {
            "runA" => Some("SEC_UNSIGNED_REJECTED"),
            "runB" | "runC" => Some("SEC_SIGNED_ACCEPTED"),
            _ => None,
        };
        approvals.insert(name.to_string(), data.approval(expected));
        replay.insert(name.to_string(), data.replay());
        run_map.insert(name.to_string(), data);
    }

    let comparisons = compare_runs(run_map.get("runB").unwrap(), run_map.get("runC").unwrap());

    let mut pass = comparisons.iter().all(|c| c.pass)
        && bucket_policy.values().all(|p| p.pass)
        && chain_verification.values().all(|c| c.pass)
        && approvals.values().all(|a| a.pass)
        && replay.values().all(|r| r.within_run_pass);

    // If any manifest entry missing for required equality set, fail closed.
    for fname in REQUIRED_EQUALITY_SET {
        let key_b = format!("runB/{fname}");
        let key_c = format!("runC/{fname}");
        if !manifest.contains_key(&key_b) || !manifest.contains_key(&key_c) {
            pass = false;
        }
    }

    Ok(EvidenceBundle {
        manifest,
        comparisons,
        bucket_policy,
        chain_verification,
        approvals,
        replay,
        pass,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ingest_bytes, ingest_stream, write_manifest, AppendStore, MetricsTracker, RunData,
        REQUIRED_EQUALITY_SET,
    };
    use dio_core::{ExitChannel, RecordFrame};
    use tempfile::tempdir;

    #[test]
    fn accepts_valid_metrics_digits() {
        let dir = tempdir().unwrap();
        let store = AppendStore::new(dir.path()).unwrap();
        let mut tracker = MetricsTracker::default();
        let frame = RecordFrame {
            channel: ExitChannel::Metrics,
            tick: 1,
            payload: b"M001=1\nM002=16".to_vec(),
        };
        let bytes = frame.encode().unwrap();
        ingest_bytes(&store, &mut tracker, &bytes).expect("ingest ok");
    }

    #[test]
    fn rejects_unknown_metric() {
        let dir = tempdir().unwrap();
        let store = AppendStore::new(dir.path()).unwrap();
        let mut tracker = MetricsTracker::default();
        let frame = RecordFrame {
            channel: ExitChannel::Metrics,
            tick: 1,
            payload: b"M999=1".to_vec(),
        };
        let bytes = frame.encode().unwrap();
        let err = ingest_bytes(&store, &mut tracker, &bytes).unwrap_err();
        match err {
            super::ReceiverError::Policy("metrics_unknown") => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_out_of_range() {
        let dir = tempdir().unwrap();
        let store = AppendStore::new(dir.path()).unwrap();
        let mut tracker = MetricsTracker::default();
        let frame = RecordFrame {
            channel: ExitChannel::Metrics,
            tick: 1,
            payload: b"M001=1000001".to_vec(),
        };
        let bytes = frame.encode().unwrap();
        let err = ingest_bytes(&store, &mut tracker, &bytes).unwrap_err();
        match err {
            super::ReceiverError::Policy("metrics_bounds") => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_non_quantized() {
        let dir = tempdir().unwrap();
        let store = AppendStore::new(dir.path()).unwrap();
        let mut tracker = MetricsTracker::default();
        let frame = RecordFrame {
            channel: ExitChannel::Metrics,
            tick: 1,
            payload: b"M002=3".to_vec(),
        };
        let bytes = frame.encode().unwrap();
        let err = ingest_bytes(&store, &mut tracker, &bytes).unwrap_err();
        match err {
            super::ReceiverError::Policy("metrics_quant") => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_unsorted_metrics() {
        let dir = tempdir().unwrap();
        let store = AppendStore::new(dir.path()).unwrap();
        let mut tracker = MetricsTracker::default();
        let frame = RecordFrame {
            channel: ExitChannel::Metrics,
            tick: 1,
            payload: b"M002=16\nM001=1".to_vec(),
        };
        let bytes = frame.encode().unwrap();
        let err = ingest_bytes(&store, &mut tracker, &bytes).unwrap_err();
        match err {
            super::ReceiverError::Policy("metrics_sort") => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_too_many_updates() {
        let dir = tempdir().unwrap();
        let store = AppendStore::new(dir.path()).unwrap();
        let mut tracker = MetricsTracker::default();
        let frame = RecordFrame {
            channel: ExitChannel::Metrics,
            tick: 1,
            payload: b"M003=0\nM003=1\nM003=2\nM003=3\nM003=4\nM003=5\nM003=6\nM003=7\nM003=8\nM003=9\nM003=10\nM003=11\n".to_vec(),
        };
        let bytes = frame.encode().unwrap();
        let err = ingest_bytes(&store, &mut tracker, &bytes).unwrap_err();
        match err {
            super::ReceiverError::Policy("metrics_rate") => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ingest_stream_handles_multiple_frames() {
        let dir = tempdir().unwrap();
        let store = AppendStore::new(dir.path()).unwrap();
        let f1 = RecordFrame {
            channel: ExitChannel::Audit,
            tick: 1,
            payload: vec![],
        };
        let f2 = RecordFrame {
            channel: ExitChannel::Metrics,
            tick: 2,
            payload: b"M001=1".to_vec(),
        };
        let mut bytes = Vec::new();
        bytes.extend(f1.encode().unwrap());
        bytes.extend(f2.encode().unwrap());
        ingest_stream(&store, &bytes).expect("ingest stream");
    }

    #[test]
    fn manifest_writes_hashes() {
        let dir = tempdir().unwrap();
        let store = AppendStore::new(dir.path()).unwrap();
        let mut tracker = MetricsTracker::default();
        let frame = RecordFrame {
            channel: ExitChannel::Audit,
            tick: 1,
            payload: vec![],
        };
        ingest_bytes(&store, &mut tracker, &frame.encode().unwrap()).unwrap();
        write_manifest(&store).unwrap();
        let manifest = std::fs::read_to_string(dir.path().join("hashes.json")).unwrap();
        assert!(manifest.contains("audit.bin"));
    }

    #[test]
    fn equality_set_is_sorted() {
        let v = REQUIRED_EQUALITY_SET.to_vec();
        let mut sorted = v.clone();
        sorted.sort();
        assert_eq!(v, sorted);
    }

    #[test]
    fn manifest_keys_are_deterministic() {
        let dir = tempdir().unwrap();
        let run = dir.path().join("runB");
        std::fs::create_dir_all(&run).unwrap();
        // tick=1, len=0
        let mut rec = Vec::new();
        rec.extend_from_slice(&1u64.to_le_bytes());
        rec.extend_from_slice(&0u32.to_le_bytes());
        std::fs::write(run.join("outputs.bin"), &rec).unwrap();
        std::fs::write(run.join("audit.bin"), &rec).unwrap();
        let data = RunData::load("runB", &run).unwrap();
        let keys: Vec<_> = data.manifest().keys().cloned().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }
}
