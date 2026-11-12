use sawp::parser::{Direction, Parse};
use sawp::protocol::Protocol;
use sawp_ike::payloads::PayloadData;
use sawp_ike::*;

#[test]
fn test_name() {
    assert_eq!(Ike::name(), "ike");
}

/// Regression test for memory amplification DoS via Delete payload with
/// spi_size=0 and high num_spi. Prior to the fix, count(take(0), n)
/// allocated up to 65535 empty vecs.
#[test]
fn regression_delete_zero_spi_size_amplification() {
    // IKEv2 header (28 bytes) + one Delete payload (8 bytes) with
    // spi_size = 0 and num_spi = 0xFFFF.
    #[rustfmt::skip]
    let input: &[u8] = &[
        // initiator_spi (non-zero so the optional non-ESP marker is not consumed)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        // responder_spi
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // next_payload = Delete (42), version = 2.0, exchange = Informational (37), flags = INITIATOR
        0x2a, 0x20, 0x25, 0x08,
        // message_id
        0x00, 0x00, 0x00, 0x01,
        // length = 28 + 8 = 36
        0x00, 0x00, 0x00, 0x24,
        // Delete payload: next_payload = NoNextPayload, critical/reserved = 0, payload_length = 8
        0x00, 0x00, 0x00, 0x08,
        // protocol_id = 1, spi_size = 0, num_spi = 0xFFFF
        0x01, 0x00, 0xff, 0xff,
    ];

    let ike = Ike::default();
    // Must not panic / OOM regardless of outcome.
    let result = ike.parse(input, Direction::Unknown);
    let (_rest, msg) = result.expect("malicious delete payload should parse without error");
    match msg {
        Some(Message::Ike(m)) => {
            assert_eq!(m.payloads.len(), 1);
            match &m.payloads[0].data {
                PayloadData::Delete {
                    spi_size,
                    num_spi,
                    spis,
                    ..
                } => {
                    assert_eq!(*spi_size, 0);
                    assert_eq!(*num_spi, 0xffff);
                    // The fix short-circuits to an empty list when spi_size == 0,
                    // preventing 65535 empty-Vec allocations.
                    assert!(spis.is_empty());
                }
                other => panic!("expected Delete payload, got {:?}", other),
            }
        }
        other => panic!("expected Ike message, got {:?}", other),
    }
}

/// Regression test for the IKEv1 variant of the same memory amplification
/// DoS in the V1Delete payload (payload type 12).
#[test]
fn regression_v1_delete_zero_spi_size_amplification() {
    // IKEv1 header (28 bytes) + one V1Delete payload (12 bytes) with
    // spi_size = 0 and num_spi = 0xFFFF.
    #[rustfmt::skip]
    let input: &[u8] = &[
        // initiator_spi
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        // responder_spi
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        // next_payload = V1Delete (12), version = 1.0, exchange = InformationalV1 (5), flags = 0
        0x0c, 0x10, 0x05, 0x00,
        // message_id
        0x00, 0x00, 0x00, 0x01,
        // length = 28 + 12 = 40
        0x00, 0x00, 0x00, 0x28,
        // V1Delete payload: next_payload = NoNextPayload, reserved = 0, payload_length = 12
        0x00, 0x00, 0x00, 0x0c,
        // doi
        0x00, 0x00, 0x00, 0x01,
        // protocol_id = 1, spi_size = 0, num_spi = 0xFFFF
        0x01, 0x00, 0xff, 0xff,
    ];

    let ike = Ike::default();
    // Must not panic / OOM regardless of outcome.
    let result = ike.parse(input, Direction::Unknown);
    let (_rest, msg) = result.expect("malicious v1 delete payload should parse without error");
    match msg {
        Some(Message::Ike(m)) => {
            assert_eq!(m.payloads.len(), 1);
            match &m.payloads[0].data {
                PayloadData::V1Delete {
                    spi_size,
                    num_spi,
                    spis,
                    ..
                } => {
                    assert_eq!(*spi_size, 0);
                    assert_eq!(*num_spi, 0xffff);
                    assert!(spis.is_empty());
                }
                other => panic!("expected V1Delete payload, got {:?}", other),
            }
        }
        other => panic!("expected Ike message, got {:?}", other),
    }
}
