//! Shared binary wire encoding for derived workspace caches.
//!
//! Cache owners remain responsible for explicit schema versions and pipeline
//! fingerprints. This module only centralizes the maintained MessagePack
//! codec, so every sidecar uses the same serializer configuration and error
//! types.

use std::io::{Read, Write};

use rmp_serde::{Deserializer, Serializer};
use serde::{de::DeserializeOwned, Serialize};

/// Error returned while encoding a MessagePack value.
pub type EncodeError = rmp_serde::encode::Error;

/// Error returned while decoding a MessagePack value.
pub type DecodeError = rmp_serde::decode::Error;

/// Encode `value` as MessagePack bytes.
pub fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, EncodeError> {
    rmp_serde::to_vec(value)
}

/// Decode a complete MessagePack value from `bytes`.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    rmp_serde::from_slice(bytes)
}

/// Encode `value` as MessagePack directly into `writer`.
pub fn encode_to_writer<W, T>(writer: W, value: &T) -> Result<(), EncodeError>
where
    W: Write,
    T: Serialize + ?Sized,
{
    value.serialize(&mut Serializer::new(writer))
}

/// Decode one MessagePack value directly from `reader`.
pub fn decode_from_reader<R, T>(reader: R) -> Result<T, DecodeError>
where
    R: Read,
    T: DeserializeOwned,
{
    T::deserialize(&mut Deserializer::new(reader))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq, serde::Deserialize, Serialize)]
    struct Record {
        version: u32,
        fingerprint: u128,
        labels: Vec<String>,
    }

    fn record() -> Record {
        Record {
            version: 7,
            fingerprint: (u128::from(u64::MAX) << 64) | 0x1234,
            labels: vec!["source".into(), "sink".into()],
        }
    }

    #[test]
    fn buffer_round_trip_is_deterministic() {
        let first = encode(&record()).expect("encode");
        let second = encode(&record()).expect("encode");
        assert_eq!(first, second);
        assert_eq!(decode::<Record>(&first).expect("decode"), record());
    }

    #[test]
    fn streaming_round_trip() {
        let mut encoded = Vec::new();
        encode_to_writer(&mut encoded, &record()).expect("encode");
        assert_eq!(
            decode_from_reader::<_, Record>(encoded.as_slice()).expect("decode"),
            record()
        );
    }

    #[test]
    fn corrupt_payload_is_rejected() {
        assert!(decode::<Record>(&[0xc1]).is_err());
    }
}
