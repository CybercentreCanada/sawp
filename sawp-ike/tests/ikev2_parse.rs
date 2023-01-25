use rstest::rstest;
use sawp::error::{Error, Result};
use sawp::parser::{Direction, Parse};
use sawp::protocol::Protocol;
use sawp_flags::Flag;
use sawp_ike::{header::*, payloads::*, *};

// Full packet parse tests. Parses header and full body of provided payload, including version
// detection.
#[rstest(input, expected, case::empty(b"", Err(Error::incomplete_needed(4))),
        case::nonzero_messageid_and_responder_spi_in_init(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
            0x00, 0x20, 0x22, 0x08, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x1c
        ], Ok((0, Some(
            Message::Ike(IkeMessage {
                header: Header {
                    initiator_spi: 18446744073709551615,
                    responder_spi: 17216961135462248174,
                    raw_next_payload: 0,
                    next_payload: PayloadType::NoNextPayload,
                    version: 0x20,
                    major_version: 2,
                    minor_version: 0,
                    raw_exchange_type: 34,
                    exchange_type: ExchangeType::IkeSaInit,
                    flags: 8,
                    message_id: 16909060,
                    length: 28
                },
                payloads: Vec::new(),
                error_flags: ErrorFlags::NonZeroMessageIdInInit | ErrorFlags::NonZeroResponderSpiInInit
            })
        )))),
        case::invalid_version(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
            0x01, 0x31,
        ], Err(Error::parse(None))
        ),
        case::unknown_and_invalid_top_level_payloads(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0x20, 0x22, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x02, 0x00, 0x00, 0x05,
            0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
        ], Ok((0, Some(
           Message::Ike(IkeMessage {
                header: Header {
                    initiator_spi: 18446744073709551615,
                    responder_spi: 0,
                    raw_next_payload: 255,
                    next_payload: PayloadType::Unknown,
                    version: 0x20,
                    major_version: 2,
                    minor_version: 0,
                    raw_exchange_type: 34,
                    exchange_type: ExchangeType::IkeSaInit,
                    flags: 8,
                    message_id: 0,
                    length: 38,
                },
                payloads: vec![
                    Payload {
                        raw_next_payload: 2,
                        next_payload: PayloadType::Unknown, // 2 is V1Proposal but it is invalid in this spot
                        critical_bit: Some(0),
                        reserved: 0,
                        payload_length: 5,
                        data: PayloadData::Unknown(vec![0x00]),
                    },
                    Payload {
                        raw_next_payload: 0,
                        next_payload: PayloadType::NoNextPayload,
                        critical_bit: Some(0),
                        reserved: 0,
                        payload_length: 5,
                        data: PayloadData::Unknown(vec![0x00]),
                    }
                ],
                error_flags: ErrorFlags::UnknownPayload.into()
            })
        )))),
        // https://wiki.wireshark.org/SampleCaptures#example-2-dissection-of-encrypted-and-udp-encapsulated-ikev2-and-esp-messages
        case::ike_sa_init_request(&[
            0x89, 0x92, 0x2c, 0x91, 0x5f, 0x35, 0x57, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x21, 0x20, 0x22, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2c, 0x22, 0x00, 0x00, 0x28,
            0x00, 0x00, 0x00, 0x24, 0x01, 0x01, 0x00, 0x03, 0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x14,
            0x80, 0x0e, 0x01, 0x00, 0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08,
            0x04, 0x00, 0x00, 0x13, 0x28, 0x00, 0x00, 0x48, 0x00, 0x13, 0x00, 0x00, 0xdb, 0x25, 0x31, 0x78,
            0x44, 0x0c, 0xe7, 0x76, 0xa7, 0x94, 0x13, 0x3c, 0xb8, 0xb6, 0x9e, 0x5e, 0xb0, 0x74, 0x73, 0x35,
            0x36, 0x57, 0x0c, 0x64, 0xd7, 0xb6, 0x30, 0x54, 0x9c, 0x89, 0x9c, 0x07, 0x12, 0xd8, 0x28, 0xb3,
            0x71, 0x68, 0x50, 0x08, 0x85, 0xe0, 0x51, 0x02, 0x45, 0x78, 0xaf, 0xc7, 0x5c, 0x10, 0x1f, 0x73,
            0xb8, 0x94, 0x3c, 0xad, 0x62, 0xd7, 0x4a, 0x30, 0xf2, 0xbe, 0x1f, 0xca, 0x2b, 0x00, 0x00, 0x2c,
            0x09, 0xcb, 0x53, 0x8b, 0x2c, 0x3d, 0xbd, 0x4d, 0x0b, 0xb0, 0xee, 0xc8, 0xd3, 0x18, 0xcb, 0x80,
            0x1a, 0x9b, 0x47, 0x15, 0xb2, 0x07, 0x82, 0x8d, 0x9b, 0x5f, 0xf1, 0xf4, 0xec, 0x64, 0xed, 0x58,
            0x86, 0x37, 0x07, 0xbc, 0xf1, 0x4c, 0xcf, 0x05, 0x2b, 0x00, 0x00, 0x14, 0xeb, 0x4c, 0x1b, 0x78,
            0x8a, 0xfd, 0x4a, 0x9c, 0xb7, 0x73, 0x0a, 0x68, 0xd5, 0x6c, 0x53, 0x21, 0x2b, 0x00, 0x00, 0x14,
            0xc6, 0x1b, 0xac, 0xa1, 0xf1, 0xa6, 0x0c, 0xc1, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x2b, 0x00, 0x00, 0x18, 0x40, 0x48, 0xb7, 0xd5, 0x6e, 0xbc, 0xe8, 0x85, 0x25, 0xe7, 0xde, 0x7f,
            0x00, 0xd6, 0xc2, 0xd3, 0xc0, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x14, 0x40, 0x48, 0xb7, 0xd5,
            0x6e, 0xbc, 0xe8, 0x85, 0x25, 0xe7, 0xde, 0x7f, 0x00, 0xd6, 0xc2, 0xd3, 0x29, 0x00, 0x00, 0x08,
            0x00, 0x00, 0x40, 0x2e, 0x29, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x16, 0x00, 0x00, 0x00, 0x10,
            0x00, 0x00, 0x40, 0x2f, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
        ], Ok((0, Some(
            Message::Ike(IkeMessage {
                header: Header {
                    initiator_spi: 0x89922c915f35570e,
                    responder_spi: 0,
                    raw_next_payload: 33,
                    next_payload: PayloadType::SecurityAssociation,
                    version: 0x20,
                    major_version: 2,
                    minor_version: 0,
                    raw_exchange_type: 34,
                    exchange_type: ExchangeType::IkeSaInit,
                    flags: 0x08,
                    message_id: 0,
                    length: 300,
                },
                payloads: vec![
                    Payload {
                        raw_next_payload: 34,
                        next_payload: PayloadType::KeyExchange,
                        critical_bit: Some(0),
                        reserved: 0,
                        payload_length: 40,
                        data: PayloadData::SecurityAssociation(vec![Proposal {
                            last_substruc: 0,
                            reserved: 0,
                            proposal_length: 36,
                            proposal_num: 1,
                            protocol_id: 1,
                            spi_size: 0,
                            num_transforms: 3,
                            spi: Vec::new(),
                            transforms: vec![
                                Transform {
                                    last_substruc: 3,
                                    reserved: 0,
                                    transform_length: 12,
                                    transform_type: TransformType::EncryptionAlgorithm,
                                    reserved2: 0,
                                    transform_id: 20,
                                    attributes: vec![Attribute {
                                        att_format: AttributeFormat::TypeValue,
                                        att_type: 14,
                                        att_length: 0,
                                        att_value: vec![0x01, 0x00],
                                    }],
                                },
                                Transform {
                                    last_substruc: 3,
                                    reserved: 0,
                                    transform_length: 8,
                                    transform_type: TransformType::PseudoRandomFunction,
                                    reserved2: 0,
                                    transform_id: 5,
                                    attributes: Vec::new(),
                                },
                                Transform {
                                    last_substruc: 0,
                                    reserved: 0,
                                    transform_length: 8,
                                    transform_type: TransformType::DiffieHellmanGroup,
                                    reserved2: 0,
                                    transform_id: 19,
                                    attributes: Vec::new(),
                                },
                            ],
                        }]),
                    },
                    Payload {
                        raw_next_payload: 40,
                        next_payload: PayloadType::Nonce,
                        critical_bit: Some(0),
                        reserved: 0,
                        payload_length: 72,
                        data: PayloadData::KeyExchange {
                            diffie_hellman_group_num: 19,
                            reserved: 0,
                            key_exchange_data: vec![
                                0xdb, 0x25, 0x31, 0x78, 0x44, 0x0c, 0xe7, 0x76, 0xa7, 0x94, 0x13, 0x3c,
                                0xb8, 0xb6, 0x9e, 0x5e, 0xb0, 0x74, 0x73, 0x35, 0x36, 0x57, 0x0c, 0x64,
                                0xd7, 0xb6, 0x30, 0x54, 0x9c, 0x89, 0x9c, 0x07, 0x12, 0xd8, 0x28, 0xb3,
                                0x71, 0x68, 0x50, 0x08, 0x85, 0xe0, 0x51, 0x02, 0x45, 0x78, 0xaf, 0xc7,
                                0x5c, 0x10, 0x1f, 0x73, 0xb8, 0x94, 0x3c, 0xad, 0x62, 0xd7, 0x4a, 0x30,
                                0xf2, 0xbe, 0x1f, 0xca,
                            ],
                        },
                    },
                    Payload {
                        raw_next_payload: 43,
                        next_payload: PayloadType::VendorID,
                        critical_bit: Some(0),
                        reserved: 0,
                        payload_length: 44,
                        data: PayloadData::Nonce(vec![
                            0x09, 0xcb, 0x53, 0x8b, 0x2c, 0x3d, 0xbd, 0x4d, 0x0b, 0xb0, 0xee, 0xc8, 0xd3,
                            0x18, 0xcb, 0x80, 0x1a, 0x9b, 0x47, 0x15, 0xb2, 0x07, 0x82, 0x8d, 0x9b, 0x5f,
                            0xf1, 0xf4, 0xec, 0x64, 0xed, 0x58, 0x86, 0x37, 0x07, 0xbc, 0xf1, 0x4c, 0xcf,
                            0x05,
                        ]),
                    },
                    Payload {
                        raw_next_payload: 43,
                        next_payload: PayloadType::VendorID,
                        critical_bit: Some(0),
                        reserved: 0,
                        payload_length: 20,
                        data: PayloadData::VendorId(vec![
                            0xeb, 0x4c, 0x1b, 0x78, 0x8a, 0xfd, 0x4a, 0x9c, 0xb7, 0x73, 0x0a, 0x68, 0xd5,
                            0x6c, 0x53, 0x21,
                        ]),
                    },
                    Payload {
                        raw_next_payload: 43,
                        next_payload: PayloadType::VendorID,
                        critical_bit: Some(0),
                        reserved: 0,
                        payload_length: 20,
                        data: PayloadData::VendorId(vec![
                            0xc6, 0x1b, 0xac, 0xa1, 0xf1, 0xa6, 0x0c, 0xc1, 0x08, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00,
                        ]),
                    },
                    Payload {
                        raw_next_payload: 43,
                        next_payload: PayloadType::VendorID,
                        critical_bit: Some(0),
                        reserved: 0,
                        payload_length: 24,
                        data: PayloadData::VendorId(vec![
                            0x40, 0x48, 0xb7, 0xd5, 0x6e, 0xbc, 0xe8, 0x85, 0x25, 0xe7, 0xde, 0x7f, 0x00,
                            0xd6, 0xc2, 0xd3, 0xc0, 0x00, 0x00, 0x00,
                        ]),
                    },
                    Payload {
                        raw_next_payload: 41,
                        next_payload: PayloadType::Notify,
                        critical_bit: Some(0),
                        reserved: 0,
                        payload_length: 20,
                        data: PayloadData::VendorId(vec![
                            0x40, 0x48, 0xb7, 0xd5, 0x6e, 0xbc, 0xe8, 0x85, 0x25, 0xe7, 0xde, 0x7f, 0x00,
                            0xd6, 0xc2, 0xd3,
                        ]),
                    },
                    Payload {
                        raw_next_payload: 41,
                        next_payload: PayloadType::Notify,
                        critical_bit: Some(0),
                        reserved: 0,
                        payload_length: 8,
                        data: PayloadData::Notify {
                            protocol_id: 0,
                            spi_size: 0,
                            spi: Vec::new(),
                            notify_message_type: 16430,
                            notification_data: Vec::new(),
                        },
                    },
                    Payload {
                        raw_next_payload: 41,
                        next_payload: PayloadType::Notify,
                        critical_bit: Some(0),
                        reserved: 0,
                        payload_length: 8,
                        data: PayloadData::Notify {
                            protocol_id: 0,
                            spi_size: 0,
                            spi: Vec::new(),
                            notify_message_type: 16406,
                            notification_data: Vec::new(),
                        },
                    },
                    Payload {
                        raw_next_payload: 0,
                        next_payload: PayloadType::NoNextPayload,
                        critical_bit: Some(0),
                        reserved: 0,
                        payload_length: 16,
                        data: PayloadData::Notify {
                            protocol_id: 0,
                            spi_size: 0,
                            spi: Vec::new(),
                            notify_message_type: 16431,
                            notification_data: vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04],
                        },
                    },
                ],
                error_flags: ErrorFlags::none(),
            })
        )))),
    )]
fn ikev2_full_parse(input: &[u8], expected: Result<(usize, Option<<Ike as Protocol>::Message>)>) {
    let ike = Ike::default();
    assert_eq!(
        ike.parse(input, Direction::Unknown)
            .map(|(left, msg)| (left.len(), msg)),
        expected
    );
}

// Payload only tests. Only parses the unique part of a given payload (without Generic Payload
// Header).
#[rstest(input, ptype, expected,
    case::configuration(
        &[0x01, 0x00, 0x00, 0x00, 0x70, 0x38, 0x00, 0x02, 0x02, 0x40],
        PayloadType::Configuration,
        (0,(
                PayloadData::Configuration {
                    cfg_type: 1,
                    reserved: 0,
                    attributes: vec![Attribute {
                        att_format: AttributeFormat::TypeLengthValue,
                        att_type: 28728,
                        att_length: 2,
                        att_value: vec![0x02, 0x40],
                    }],
                },
                ErrorFlags::none()
                )
        )
    ),
    case::certificate(
        &[0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14],
        PayloadType::Certificate,
        (0,(
            PayloadData::Certificate(Certificate {
                cert_encoding: 4,
                certificate_data: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            }),
            ErrorFlags::none()
        ))
    ),
    case::certificate_request(
        &[0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14],
        PayloadType::CertificateRequest,
        (0,(
                PayloadData::CertificateRequest(CertificateRequest {
                    cert_encoding: 4,
                    certification_authority: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
                }),
                ErrorFlags::none()
        ))
    ),
    case::authentication(
        &[0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04],
        PayloadType::Authentication,
        (0,(
            PayloadData::Authentication {
                auth_method: 1,
                reserved: 0,
                authentication_data: vec![1, 2, 3, 4],
            },
            ErrorFlags::none()
        ))
    ),
    case::traffic_selector_init_v4(
        &[0x01, 0x00, 0x00, 0x00, 0x07, 0x11, 0x00, 0x10, 0x00, 0x01, 0x00, 0x02, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01],
        PayloadType::TrafficSelectorInitiator,
        (0,(
            PayloadData::TrafficSelectorInitiator(
                TrafficSelector {
                    number_ts: 1,
                    reserved: 0,
                    traffic_selectors: vec![
                        TrafficSelectorBody {
                            ts_type: 7,
                            ip_protocol_id: 17,
                            selector_length: 16,
                            address: Address::Ipv4(
                                AddressV4 {
                                    start_port: 1,
                                    end_port: 2,
                                    starting_address: std::net::Ipv4Addr::new(127, 0, 0, 1),
                                    ending_address: std::net::Ipv4Addr::new(127, 0, 0, 1),
                                }
                            )
                        }
                    ]
                }
            ),
            ErrorFlags::none()
        ))
    ),
    case::traffic_selector_resp_v6(
        &[0x01, 0x00, 0x00, 0x00, 0x08, 0x11, 0x00, 0x28, 0x00, 0x01, 0x00, 0x02, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd],
        PayloadType::TrafficSelectorResponder,
        (0,(
            PayloadData::TrafficSelectorResponder(
                TrafficSelector {
                    number_ts: 1,
                    reserved: 0,
                    traffic_selectors: vec![
                        TrafficSelectorBody {
                            ts_type: 8,
                            ip_protocol_id: 17,
                            selector_length: 40,
                            address: Address::Ipv6(AddressV6 {
                                start_port: 1,
                                end_port: 2,
                                starting_address: [0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee].into(),
                                ending_address: [0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd].into(),
                            }),
                        }
                    ]
                }
            ),
            ErrorFlags::none(),
        ))
    ),
    case::delete(
        &[0x01, 0x01, 0x00, 0x02, 0x01, 0x02],
        PayloadType::Delete,
        (0,(
            PayloadData::Delete {
                protocol_id: 1,
                spi_size: 1,
                num_spi: 2,
                spis: vec![vec![1], vec![2]],
            },
            ErrorFlags::none()
        ))
    ),
    case::parse_identification(
        &[0x01, 0x00, 0x00, 0x00, 0x01],
        PayloadType::IdentificationInitiator,
        (0,(
            PayloadData::IdentificationInit(
                Identification {
                    id_type: 1,
                    reserved: 0,
                    identification_data: vec![1],
                }
            ),
            ErrorFlags::none()
        ))
    ),
    case::eap(
        &[0x01, 0x02, 0x00, 0x06, 0x03, 0x04],
        PayloadType::ExtensibleAuthenticationProtocol,
        (0,(
            PayloadData::ExtensibleAuthenticationProtocol {
                code: 1,
                identifier: 2,
                length: 6,
                r#type: 3,
                type_data: vec![0x04],
            },
            ErrorFlags::none()
        ))
    ),
)]
fn ikev2_payload_parse(
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

#[rstest(input, expected,
    case::udp_encapsulation(
        &[
            // IKE
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xee, 0xee, 0xee, 0xee,
            0xee, 0xee, 0xee, 0xee, 0x00, 0x20, 0x22, 0x08, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x1c,
            // ESP
            0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x01
        ],
        &[
             Some(Message::Ike(IkeMessage {
                header: Header {
                    initiator_spi: 18446744073709551615,
                    responder_spi: 17216961135462248174,
                    raw_next_payload: 0,
                    next_payload: PayloadType::NoNextPayload,
                    version: 0x20,
                    major_version: 2,
                    minor_version: 0,
                    raw_exchange_type: 34,
                    exchange_type: ExchangeType::IkeSaInit,
                    flags: 8,
                    message_id: 16909060,
                    length: 28
                },
                payloads: Vec::new(),
                error_flags: ErrorFlags::NonZeroMessageIdInInit | ErrorFlags::NonZeroResponderSpiInInit
            })),
            Some(Message::Esp(EspMessage {
                spi: 16909060,
                sequence: 1,
            })),
        ]
    )
    )]
fn esp(input: &[u8], expected: &[Option<sawp_ike::Message>; 2]) {
    let ike = Ike::default();
    let message1 = ike.parse(input, Direction::Unknown);
    assert!(message1.is_ok());
    let (input, message1) = message1.unwrap();

    let message2 = ike.parse(input, Direction::Unknown);
    assert!(message2.is_ok());
    let (input, message2) = message2.unwrap();

    assert_eq!(input, &[]);
    assert_eq!(expected, &[message1, message2]);
}
