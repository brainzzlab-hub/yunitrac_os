#![forbid(unsafe_code)]

pub const FRAME_MAGIC: [u8; 4] = *b"DIO1";
pub const FRAME_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 20;
pub const MAX_PAYLOAD_LEN: usize = u32::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitChannel {
    Audit = 0,
    Metrics = 1,
    Security = 2,
    Logs = 3,
}

impl ExitChannel {
    fn from_u8(value: u8) -> Result<Self, FrameError> {
        match value {
            0 => Ok(Self::Audit),
            1 => Ok(Self::Metrics),
            2 => Ok(Self::Security),
            3 => Ok(Self::Logs),
            other => Err(FrameError::UnknownChannel(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordFrame {
    pub channel: ExitChannel,
    pub tick: u64,
    pub payload: Vec<u8>,
}

impl RecordFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(FrameError::PayloadTooLarge(self.payload.len()));
        }

        let mut bytes = Vec::with_capacity(HEADER_LEN + self.payload.len());
        bytes.extend_from_slice(&FRAME_MAGIC);
        bytes.push(FRAME_VERSION);
        bytes.push(self.channel as u8);
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&self.tick.to_le_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < HEADER_LEN {
            return Err(FrameError::TooShort {
                minimum: HEADER_LEN,
                actual: bytes.len(),
            });
        }

        if bytes[0..4] != FRAME_MAGIC {
            return Err(FrameError::InvalidMagic);
        }

        let version = bytes[4];
        if version != FRAME_VERSION {
            return Err(FrameError::UnsupportedVersion(version));
        }

        let channel = ExitChannel::from_u8(bytes[5])?;

        let mut reserved_bytes = [0_u8; 2];
        reserved_bytes.copy_from_slice(&bytes[6..8]);
        let reserved = u16::from_le_bytes(reserved_bytes);
        if reserved != 0 {
            return Err(FrameError::NonZeroReserved(reserved));
        }

        let mut tick_bytes = [0_u8; 8];
        tick_bytes.copy_from_slice(&bytes[8..16]);
        let tick = u64::from_le_bytes(tick_bytes);

        let mut payload_len_bytes = [0_u8; 4];
        payload_len_bytes.copy_from_slice(&bytes[16..20]);
        let payload_len = u32::from_le_bytes(payload_len_bytes) as usize;

        let expected_total = HEADER_LEN
            .checked_add(payload_len)
            .ok_or(FrameError::PayloadTooLarge(payload_len))?;

        if bytes.len() < expected_total {
            return Err(FrameError::TruncatedPayload {
                expected: payload_len,
                actual: bytes.len().saturating_sub(HEADER_LEN),
            });
        }

        if bytes.len() > expected_total {
            return Err(FrameError::TrailingBytes(bytes.len() - expected_total));
        }

        Ok(Self {
            channel,
            tick,
            payload: bytes[HEADER_LEN..expected_total].to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    TooShort { minimum: usize, actual: usize },
    InvalidMagic,
    UnsupportedVersion(u8),
    UnknownChannel(u8),
    NonZeroReserved(u16),
    PayloadTooLarge(usize),
    TruncatedPayload { expected: usize, actual: usize },
    TrailingBytes(usize),
}

#[cfg(test)]
mod tests {
    use super::{ExitChannel, FrameError, RecordFrame, HEADER_LEN};

    #[test]
    fn encode_is_deterministic() {
        let frame = RecordFrame {
            channel: ExitChannel::Audit,
            tick: 7,
            payload: b"abc".to_vec(),
        };

        let first = frame.encode().expect("first encode must pass");
        let second = frame.encode().expect("second encode must pass");

        assert_eq!(first, second);
        assert_eq!(
            first,
            vec![
                b'D', b'I', b'O', b'1', 1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, b'a', b'b',
                b'c'
            ]
        );
    }

    #[test]
    fn decode_round_trip() {
        let frame = RecordFrame {
            channel: ExitChannel::Metrics,
            tick: 99,
            payload: vec![1, 2, 3, 4],
        };

        let encoded = frame.encode().expect("encode must pass");
        let decoded = RecordFrame::decode(&encoded).expect("decode must pass");

        assert_eq!(frame, decoded);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut encoded = RecordFrame {
            channel: ExitChannel::Security,
            tick: 1,
            payload: vec![],
        }
        .encode()
        .expect("encode must pass");
        encoded[0] = 0;

        assert_eq!(RecordFrame::decode(&encoded), Err(FrameError::InvalidMagic));
    }

    #[test]
    fn decode_rejects_unknown_channel() {
        let mut encoded = RecordFrame {
            channel: ExitChannel::Logs,
            tick: 1,
            payload: vec![],
        }
        .encode()
        .expect("encode must pass");
        encoded[5] = 9;

        assert_eq!(
            RecordFrame::decode(&encoded),
            Err(FrameError::UnknownChannel(9))
        );
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let mut encoded = RecordFrame {
            channel: ExitChannel::Audit,
            tick: 3,
            payload: vec![1, 2, 3],
        }
        .encode()
        .expect("encode must pass");
        encoded.pop();

        assert_eq!(
            RecordFrame::decode(&encoded),
            Err(FrameError::TruncatedPayload {
                expected: 3,
                actual: 2
            })
        );
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut encoded = RecordFrame {
            channel: ExitChannel::Audit,
            tick: 3,
            payload: vec![1, 2, 3],
        }
        .encode()
        .expect("encode must pass");
        encoded.push(99);

        assert_eq!(
            RecordFrame::decode(&encoded),
            Err(FrameError::TrailingBytes(1))
        );
    }

    #[test]
    fn encode_stable_over_repeated_calls() {
        let frame = RecordFrame {
            channel: ExitChannel::Audit,
            tick: 42,
            payload: vec![7; 32],
        };
        let baseline = frame.encode().unwrap();
        for _ in 0..50 {
            assert_eq!(baseline, frame.encode().unwrap());
        }
    }

    #[test]
    fn roundtrip_various_payload_sizes() {
        for size in [0_usize, 1, 2, 3, 4, 8, 16, 64, 256, 1024, 4096] {
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let frame = RecordFrame {
                channel: ExitChannel::Metrics,
                tick: 5,
                payload,
            };
            let encoded = frame.encode().unwrap();
            let decoded = RecordFrame::decode(&encoded).unwrap();
            assert_eq!(frame, decoded);
        }
    }

    #[test]
    fn rejects_too_short() {
        let data = vec![0u8; HEADER_LEN - 1];
        assert_eq!(
            RecordFrame::decode(&data),
            Err(FrameError::TooShort {
                minimum: HEADER_LEN,
                actual: HEADER_LEN - 1
            })
        );
    }

    #[test]
    fn rejects_non_zero_reserved() {
        let mut encoded = RecordFrame {
            channel: ExitChannel::Audit,
            tick: 1,
            payload: vec![0],
        }
        .encode()
        .unwrap();
        encoded[6] = 1;
        assert_eq!(
            RecordFrame::decode(&encoded),
            Err(FrameError::NonZeroReserved(1))
        );
    }

    #[test]
    fn decode_never_panics_on_small_inputs() {
        for len in 0usize..256 {
            let buf: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(17)).collect();
            let _ = RecordFrame::decode(&buf);
        }
    }
}
