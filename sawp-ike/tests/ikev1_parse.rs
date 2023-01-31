use rstest::rstest;
use sawp::error::Result;
use sawp::parser::{Direction, Parse};
use sawp::protocol::Protocol;
use sawp_flags::Flag;
use sawp_ike::{header::*, payloads::*, *};

// Full packet parse tests. Parses header and full body of provided payload, including version
// detection.
#[rstest(input, expected,
    // Retrieved from https://github.com/vathpela/wireshark/blob/master/test/captures/ikev1-certs.pcap
    case::ike_sa_init(&[
        0xfa, 0xfa, 0xeb, 0x49, 0x38, 0x2a, 0x76, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x0d, 0x01, 0x00, 0x34,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x80, 0x0b, 0x00, 0x01, 0x80, 0x0c, 0x70, 0x80,
        0x80, 0x01, 0x00, 0x05, 0x80, 0x02, 0x00, 0x01, 0x80, 0x03, 0x00, 0x03, 0x80, 0x04, 0x00, 0x02,
        0x0d, 0x00, 0x00, 0x10, 0x4f, 0x45, 0x68, 0x79, 0x4c, 0x64, 0x41, 0x43, 0x65, 0x63, 0x66, 0x61,
        0x00, 0x00, 0x00, 0x14, 0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc,
        0x77, 0x57, 0x01, 0x00
    ], Ok((0, Some(
        Message::Ike(IkeMessage {
            header: Header {
                initiator_spi: 0xfafa_eb49_382a_763c,
                    responder_spi: 0x00,
                    next_payload: PayloadType::V1SecurityAssociation,
                    version: 0x10,
                    major_version: 1,
                    minor_version: 0,
                    exchange_type: ExchangeType::IdentityProtection,
                    flags: IkeFlags::none(),
                    message_id: 0,
                    length: 116,
            },
            payloads: vec![
                Payload {
                    next_payload: PayloadType::V1VendorID,
                    critical_bit: None,
                    reserved: 1,
                    payload_length: 52,
                    data: PayloadData::V1SecurityAssociation {
                            doi: 1,
                            situation: 1,
                            proposals: vec![
                                V1Proposal {
                                    next_payload: 0,
                                    reserved: 0,
                                    payload_length: 40,
                                    proposal_num: 0,
                                    protocol_id: 1,
                                    spi_size: 0,
                                    spi: vec![],
                                    num_transforms: 1,
                                    transforms: vec![
                                        V1Transform {
                                            next_payload: 0,
                                            reserved: 0,
                                            payload_length: 32,
                                            transform_num: 0,
                                            transform_id: 1,
                                            reserved2: 0,
                                            attributes: vec![
                                                Attribute {
                                                    att_format: AttributeFormat::TypeValue,
                                                    att_type: 11,
                                                    att_length: 0,
                                                    att_value: vec![0x00, 0x01],
                                                },
                                                Attribute {
                                                    att_format: AttributeFormat::TypeValue,
                                                    att_type: 12,
                                                    att_length: 0,
                                                    att_value: vec![0x70, 0x80],
                                                },
                                                Attribute {
                                                    att_format: AttributeFormat::TypeValue,
                                                    att_type: 1,
                                                    att_length: 0,
                                                    att_value: vec![0x00, 0x05],
                                                },
                                                Attribute {
                                                    att_format: AttributeFormat::TypeValue,
                                                    att_type: 2,
                                                    att_length: 0,
                                                    att_value: vec![0x00, 0x01],
                                                },
                                                Attribute {
                                                    att_format: AttributeFormat::TypeValue,
                                                    att_type: 3,
                                                    att_length: 0,
                                                    att_value: vec![0x00, 0x03],
                                                },
                                                Attribute {
                                                    att_format: AttributeFormat::TypeValue,
                                                    att_type: 4,
                                                    att_length: 0,
                                                    att_value: vec![0x00, 0x02],
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ]
                        },
                },
                Payload {
                    next_payload: PayloadType::V1VendorID,
                    critical_bit: None,
                    reserved: 0,
                    payload_length: 16,
                    data: PayloadData::V1VendorID(
                        vec![0x4f, 0x45, 0x68, 0x79, 0x4c, 0x64, 0x41, 0x43, 0x65, 0x63, 0x66, 0x61]
                        )
                },
                Payload {
                    next_payload: PayloadType::NoNextPayload,
                    critical_bit: None,
                    reserved: 0,
                    payload_length: 20,
                    data: PayloadData::V1VendorID(
                        vec![0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01, 0x00]
                        )
                }
            ],
            encrypted_data: Vec::with_capacity(0),
            error_flags: ErrorFlags::none() | ErrorFlags::NonZeroReserved,
            })
        )))
    ),
    case::quick_mode(
        &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Init SPI
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Resp SPI
            0x08, // Next Payload (hash)
            0x10, // Version 1
            0x20, // Quick Mode
            0x01, // Flags - Encryption
            0x01, 0x02, 0x03, 0x04, // Message ID
            0x00, 0x00, 0x00, 0x24, // Length, 8 + HEADER_LEN
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Encrypted data
        ], Ok((0, Some(
            Message::Ike(IkeMessage {
                header: Header {
                    initiator_spi: 0xffff_ffff_ffff_ffff,
                    responder_spi: 0,
                    next_payload: PayloadType::V1Hash,
                    version: 0x10,
                    major_version: 1,
                    minor_version: 0,
                    exchange_type: ExchangeType::QuickMode,
                    flags: IkeFlags::ENCRYPTED.into(),
                    message_id: 16909060,
                    length: 36,
                },
                payloads: Vec::new(),
                encrypted_data: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                error_flags: ErrorFlags::none(),
            })
        )))
    ),
)]
fn ikev1_full_parse(input: &[u8], expected: Result<(usize, Option<<Ike as Protocol>::Message>)>) {
    let ike = Ike::default();
    assert_eq!(
        ike.parse(input, Direction::Unknown)
            .map(|(left, msg)| (left.len(), msg)),
        expected
    );
}

#[rstest(input, ptype, expected,
    case::notification(
        &[0x00, 0x00, 0x00, 0x01, 0x11, 0x01, 0x00, 0x01, 0x01, 0x00],
        PayloadType::V1Notification,
        (0, (PayloadData::V1Notification {
            doi: 1,
            protocol_id: 17,
            spi_size: 1,
            notify_message_type: 1,
            spi: vec![0x01],
            notification_data: vec![0x00],
        },
        ErrorFlags::none()
        ))
    ),
    case::delete(
        &[0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x02, 0x01, 0x02],
        PayloadType::V1Delete,
        (0, (PayloadData::V1Delete {
            doi: 1,
            protocol_id: 1,
            spi_size: 1,
            num_spi: 2,
            spis: vec![vec![0x01], vec![0x02]],
        },
        ErrorFlags::none()
        ))
    ),
    case::sa_kek(
        &[0x11, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x00, 0x02, 0x01, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0x00, 0x01, 0x00, 0x02],
        PayloadType::V1SaKek,
        (0, (PayloadData::V1SaKek(
            SaKek{
                protocol: 17,
                src_id_type: 1,
                src_id_port: 1,
                src_id_data_len: 1,
                src_id_data: vec![0x01],
                dst_id_type: 2,
                dst_id_port: 2,
                dst_id_data_len: 1,
                dst_id_data: vec![0x02],
                spi: vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee],
                pop_algorithm: 1,
                pop_key_len: 2,
                attributes: vec![],
            }
        ),
        ErrorFlags::none()
        ))
    ),
    case::key_download(
        &[0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x01, 0x01],
        PayloadType::V1KeyDownload,
        (0, (PayloadData::V1KeyDownload {
            num_packets: 1,
            reserved: 0,
            key_packets: vec![KeyPacket {
                kd_type: 1,
                reserved: 0,
                kd_length: 10,
                spi_size: 1,
                spi: vec![0x01],
                attributes: vec![],
            }],
            },
            ErrorFlags::none()
        ))
    )
)]
fn ikev1_payload_parse(
    input: &[u8],
    ptype: PayloadType,
    expected: (usize, (PayloadData, sawp_flags::Flags<ErrorFlags>)),
) {
    let payload = PayloadData::parse(input, ptype);
    assert_eq!(
        payload.map(|(remain, payload)| (remain.len(), payload)),
        Ok(expected)
    );
}
