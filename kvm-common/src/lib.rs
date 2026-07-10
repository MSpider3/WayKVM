use serde::{Deserialize, Serialize};
use bincode::Options;

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct KvmEvent {
    pub event_type: u16,
    pub code: u16,
    pub value: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KvmPacket {
    Handshake { version: u32 },
    Events(Vec<KvmEvent>),
    ReleaseAll,
}

pub const PROTOCOL_VERSION: u32 = 1;

pub fn serialize_packet(packet: &KvmPacket) -> Result<Vec<u8>, bincode::Error> {
    bincode::options()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .serialize(packet)
}

pub fn deserialize_packet(bytes: &[u8]) -> Result<KvmPacket, bincode::Error> {
    bincode::options()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_roundtrip() {
        let packet = KvmPacket::Handshake {
            version: PROTOCOL_VERSION,
        };
        let serialized = serialize_packet(&packet).unwrap();
        let deserialized = deserialize_packet(&serialized).unwrap();
        match deserialized {
            KvmPacket::Handshake { version } => {
                assert_eq!(version, PROTOCOL_VERSION);
            }
            _ => panic!("Expected Handshake packet"),
        }
    }

    #[test]
    fn test_events_roundtrip() {
        let events = vec![
            KvmEvent {
                event_type: 1,
                code: 30,
                value: 1,
            },
            KvmEvent {
                event_type: 2,
                code: 0,
                value: -10,
            },
        ];
        let packet = KvmPacket::Events(events.clone());
        let serialized = serialize_packet(&packet).unwrap();
        let deserialized = deserialize_packet(&serialized).unwrap();
        match deserialized {
            KvmPacket::Events(deserialized_events) => {
                assert_eq!(deserialized_events.len(), 2);
                assert_eq!(deserialized_events[0].event_type, 1);
                assert_eq!(deserialized_events[0].code, 30);
                assert_eq!(deserialized_events[0].value, 1);
                assert_eq!(deserialized_events[1].event_type, 2);
                assert_eq!(deserialized_events[1].code, 0);
                assert_eq!(deserialized_events[1].value, -10);
            }
            _ => panic!("Expected Events packet"),
        }
    }

    #[test]
    fn test_release_all_roundtrip() {
        let packet = KvmPacket::ReleaseAll;
        let serialized = serialize_packet(&packet).unwrap();
        let deserialized = deserialize_packet(&serialized).unwrap();
        match deserialized {
            KvmPacket::ReleaseAll => {}
            _ => panic!("Expected ReleaseAll packet"),
        }
    }
}

