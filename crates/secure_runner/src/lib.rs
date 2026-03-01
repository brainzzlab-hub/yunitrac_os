#![forbid(unsafe_code)]

use dio_core::{ExitChannel, FrameError, RecordFrame};

/// Buckets exposed by the boundary runtime. Ordering is fixed and maps to dio_core exit channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    Audit,
    Metrics,
    Security,
    Outputs,
}

impl Bucket {
    fn channel(self) -> ExitChannel {
        match self {
            Bucket::Audit => ExitChannel::Audit,
            Bucket::Metrics => ExitChannel::Metrics,
            Bucket::Security => ExitChannel::Security,
            Bucket::Outputs => ExitChannel::Logs,
        }
    }
}

/// DioWriter abstracts the diode path. Implementations must be writer-only and deterministic.
pub trait DioWriter {
    fn write(&self, frame: &RecordFrame) -> Result<(), DioError>;
}

/// Minimal writer that discards frames. Useful for boundary-safe dry-runs and tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullWriter;

impl DioWriter for NullWriter {
    fn write(&self, _frame: &RecordFrame) -> Result<(), DioError> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DioError {
    kind: DioErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DioErrorKind {
    Frame(FrameError),
}

impl From<FrameError> for DioError {
    fn from(err: FrameError) -> Self {
        DioError {
            kind: DioErrorKind::Frame(err),
        }
    }
}

/// Build a deterministic RecordFrame for a bucket, tick, and payload.
/// No IO, no randomness, no clocks.
pub fn build_frame(bucket: Bucket, tick: u64, payload: Vec<u8>) -> Result<RecordFrame, DioError> {
    let channel = bucket.channel();
    let frame = RecordFrame {
        channel,
        tick,
        payload,
    };
    frame.encode()?; // validates deterministically
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::{build_frame, Bucket, DioWriter, NullWriter};
    use dio_core::ExitChannel;

    #[test]
    fn build_frame_maps_bucket_to_channel() {
        let frame = build_frame(Bucket::Security, 5, vec![1, 2, 3]).expect("build ok");
        assert_eq!(frame.channel, ExitChannel::Security);
        assert_eq!(frame.tick, 5);
        assert_eq!(frame.payload, vec![1, 2, 3]);
    }

    #[test]
    fn null_writer_discards_without_error() {
        let writer = NullWriter;
        let frame = build_frame(Bucket::Audit, 0, Vec::new()).expect("build ok");
        writer.write(&frame).expect("write ok");
    }

    #[test]
    fn frames_are_deterministic() {
        let frame = build_frame(Bucket::Outputs, 9, b"abc".to_vec()).expect("build ok");
        let first = frame.encode().expect("encode ok");
        let second = frame.encode().expect("encode ok");
        assert_eq!(first, second);
    }
}
