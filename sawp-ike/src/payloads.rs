use crate::ErrorFlags;
use crate::IResult;

use sawp_flags::{Flag, Flags};

#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

use nom::bits::streaming::take as bit_take;
use nom::bytes::streaming::take;
use nom::combinator::{complete, flat_map, map, map_parser, peek, rest};
use nom::multi::{count, length_data, many0, many1};
use nom::number::streaming::{be_u16, be_u24, be_u32, be_u8};
use nom::sequence::tuple;

use num_enum::FromPrimitive;

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, FromPrimitive, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum PayloadType {
    NoNextPayload = 0,
    // V1 Payloads
    V1SecurityAssociation = 1,
    V1Proposal = 2,
    V1Transform = 3,
    V1KeyExchange = 4,
    V1Identification = 5,
    V1Certificate = 6,
    V1CertificateRequest = 7,
    V1Hash = 8,
    V1Signature = 9,
    V1Nonce = 10,
    V1Notification = 11,
    V1Delete = 12,
    V1VendorID = 13,
    V1Reserved = 14,
    V1SaKek = 15,
    V1SaTek = 16,
    V1KeyDownload = 17,
    V1SequenceNumber = 18,
    V1ProofOfPossession = 19,
    V1NATDiscovery = 20,
    V1NATOriginalAddress = 21,
    V1GroupAssociationPolicy = 22,
    // V2 Payloads
    SecurityAssociation = 33,
    KeyExchange = 34,
    IdentificationInitiator = 35,
    IdentificationResponder = 36,
    Certificate = 37,
    CertificateRequest = 38,
    Authentication = 39,
    Nonce = 40,
    Notify = 41,
    Delete = 42,
    VendorID = 43,
    TrafficSelectorInitiator = 44,
    TrafficSelectorResponder = 45,
    EncryptedAndAuthenticated = 46,
    Configuration = 47,
    ExtensibleAuthenticationProtocol = 48,
    GenericSecurePasswordMethod = 49,
    GroupIdentification = 50,
    GroupSecurityAssociation = 51,
    KeyDownload = 52,
    EncryptedAndAuthenticatedFragment = 53,
    PuzzleSolution = 54,
    #[num_enum(default)]
    Unknown,
}

impl PayloadType {
    #[inline(always)]
    #[must_use]
    pub fn is_v1(self) -> bool {
        self as u8 <= 22 || self == Self::Unknown
    }

    #[inline(always)]
    #[must_use]
    pub fn is_v2(self) -> bool {
        self as u8 >= 33 || self == Self::Unknown || self == Self::NoNextPayload
    }
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Payload {
    pub next_payload: PayloadType,
    pub critical_bit: Option<u8>,
    pub reserved: u8,
    pub payload_length: u16,
    pub data: PayloadData,
}

const GENERIC_PAYLOAD_HEADER_LEN: u16 = 4;

impl Payload {
    /* V1 Generic Payload - RFC2408
     *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * ! Next Payload  !   RESERVED    !         Payload Length        !
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     * All payloads begin with the Generic Payload so we parse it here instead of at the start of
     * each type specific parser. In these cases the generic payload is omitted from their
     * diagrams.
     */
    pub fn parse_v1(input: &[u8], payload_type: PayloadType) -> IResult<(Self, Flags<ErrorFlags>)> {
        let mut error_flags = ErrorFlags::none();

        let (input, (raw_next_payload, reserved, payload_length)) =
            tuple((be_u8, be_u8, be_u16))(input)?;
        if reserved != 0 {
            error_flags |= ErrorFlags::NonZeroReserved;
        }
        let next_payload = PayloadType::from(raw_next_payload);
        let next_payload = if next_payload.is_v1() {
            next_payload
        } else {
            PayloadType::Unknown
        };
        if next_payload == PayloadType::Unknown {
            error_flags |= ErrorFlags::UnknownPayload;
        }
        if payload_length < GENERIC_PAYLOAD_HEADER_LEN {
            error_flags |= ErrorFlags::InvalidLength;
        }
        let (input, payload_input) =
            take(payload_length.saturating_sub(GENERIC_PAYLOAD_HEADER_LEN))(input)?;
        let (_payload_input, (payload_data, ret_err)) =
            PayloadData::parse(payload_input, payload_type)?;
        error_flags |= ret_err;

        Ok((
            input,
            (
                Self {
                    next_payload,
                    critical_bit: None,
                    reserved,
                    payload_length,
                    data: payload_data,
                },
                error_flags,
            ),
        ))
    }

    /* V2 Generic Payload - RFC7296
     *                       1                   2                   3
     *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  | Next Payload  |C|  RESERVED   |         Payload Length        |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    pub fn parse_v2(input: &[u8], payload_type: PayloadType) -> IResult<(Self, Flags<ErrorFlags>)> {
        let mut error_flags = ErrorFlags::none();

        let (input, (raw_next_payload, (critical_bit, reserved), payload_length)) =
            tuple((
                be_u8,
                map(
                    nom::bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
                        bit_take(1usize),
                        bit_take(7usize),
                    ))),
                    |(crit, res)| (Some(crit), res),
                ),
                be_u16,
            ))(input)?;

        if reserved != 0 {
            error_flags |= ErrorFlags::NonZeroReserved;
        }

        let next_payload = PayloadType::from(raw_next_payload);
        let next_payload = if next_payload.is_v2() {
            next_payload
        } else {
            PayloadType::Unknown
        };
        if next_payload == PayloadType::Unknown {
            error_flags |= ErrorFlags::UnknownPayload;
        }

        if payload_length < GENERIC_PAYLOAD_HEADER_LEN {
            error_flags |= ErrorFlags::InvalidLength;
        }
        let (input, payload_input) =
            take(payload_length.saturating_sub(GENERIC_PAYLOAD_HEADER_LEN))(input)?;
        let (_payload_input, (payload_data, err_ret)) =
            PayloadData::parse(payload_input, payload_type)?;
        error_flags |= err_ret;

        Ok((
            input,
            (
                Self {
                    next_payload,
                    critical_bit,
                    reserved,
                    payload_length,
                    data: payload_data,
                },
                error_flags,
            ),
        ))
    }
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub enum PayloadData {
    V1SecurityAssociation {
        doi: u32,
        situation: u32,
        proposals: Vec<V1Proposal>,
    },
    V1KeyExchange(Vec<u8>),
    V1Identification {
        id_type: u8,
        doi_specific_data: u32, //24 bits
        id_data: Vec<u8>,
    },
    V1Certificate(Certificate),
    V1CertificateRequest(CertificateRequest),
    V1Hash(Vec<u8>),
    V1Signature(Vec<u8>),
    V1Nonce(Vec<u8>),
    V1Notification {
        doi: u32,
        protocol_id: u8,
        spi_size: u8,
        notify_message_type: u16,
        spi: Vec<u8>,
        notification_data: Vec<u8>,
    },
    V1Delete {
        doi: u32,
        protocol_id: u8,
        spi_size: u8,
        num_spi: u16,
        spis: Vec<Vec<u8>>,
    },
    V1VendorID(Vec<u8>),
    V1SaKek(SaKek),
    V1SaTek {
        protocol_id: u8,
        payload: Vec<u8>,
    },
    V1KeyDownload {
        num_packets: u16,
        reserved: u16,
        key_packets: Vec<KeyPacket>,
    },
    V1SequenceNumber(u32),
    SecurityAssociation(Vec<Proposal>),
    KeyExchange {
        diffie_hellman_group_num: u16,
        reserved: u16,
        key_exchange_data: Vec<u8>,
    },
    TrafficSelectorInitiator(TrafficSelector),
    TrafficSelectorResponder(TrafficSelector),
    Certificate(Certificate),
    CertificateRequest(CertificateRequest),
    Authentication {
        auth_method: u8,
        reserved: u32, // 24 bits
        authentication_data: Vec<u8>,
    },
    Nonce(Vec<u8>),
    Notify {
        protocol_id: u8,
        spi_size: u8,
        notify_message_type: u16,
        spi: Vec<u8>,
        notification_data: Vec<u8>,
    },
    IdentificationInit(Identification),
    IdentificationResp(Identification),
    Delete {
        protocol_id: u8,
        spi_size: u8,
        num_spi: u16,
        spis: Vec<Vec<u8>>,
    },
    VendorId(Vec<u8>),
    EncryptedAndAuthenticated(Vec<u8>),
    Configuration {
        cfg_type: u8,
        reserved: u32,
        attributes: Vec<Attribute>,
    },
    ExtensibleAuthenticationProtocol {
        code: u8,
        identifier: u8,
        length: u16,
        r#type: u8,
        type_data: Vec<u8>,
    },
    Unknown(Vec<u8>),
}

impl PayloadData {
    pub fn parse(input: &[u8], payload_type: PayloadType) -> IResult<(Self, Flags<ErrorFlags>)> {
        match payload_type {
            // V1
            PayloadType::V1SecurityAssociation => Self::parse_v1_sa(input),
            PayloadType::V1KeyExchange => Self::parse_raw(input)
                .map(|(i, (data, errs))| (i, (Self::V1KeyExchange(data), errs))),
            PayloadType::V1Identification => Self::parse_v1_identification(input),
            PayloadType::V1Certificate => Self::parse_v1_certificate(input),
            PayloadType::V1CertificateRequest => Self::parse_v1_certificate_request(input),
            PayloadType::V1Hash => {
                Self::parse_raw(input).map(|(i, (data, errs))| (i, (Self::V1Hash(data), errs)))
            }
            PayloadType::V1Signature => {
                Self::parse_raw(input).map(|(i, (data, errs))| (i, (Self::V1Signature(data), errs)))
            }
            PayloadType::V1Nonce => {
                Self::parse_raw(input).map(|(i, (data, errs))| (i, (Self::V1Nonce(data), errs)))
            }
            PayloadType::V1Notification => Self::parse_v1_notification(input),
            PayloadType::V1Delete => Self::parse_v1_delete(input),
            PayloadType::V1VendorID => {
                Self::parse_raw(input).map(|(i, (data, errs))| (i, (Self::V1VendorID(data), errs)))
            }
            PayloadType::V1SaKek => Self::parse_v1_sa_kek(input),
            PayloadType::V1SaTek => Self::parse_v1_sa_tek(input),
            PayloadType::V1KeyDownload => Self::parse_v1_key_download(input),
            PayloadType::V1SequenceNumber => Self::parse_v1_sequence_number(input),
            // V2
            PayloadType::SecurityAssociation => Self::parse_sa(input),
            PayloadType::KeyExchange => Self::parse_ke(input),
            PayloadType::TrafficSelectorInitiator => Self::parse_traffic_selector_init(input),
            PayloadType::TrafficSelectorResponder => Self::parse_traffic_selector_resp(input),
            PayloadType::Certificate => Self::parse_certificate(input),
            PayloadType::CertificateRequest => Self::parse_certificate_request(input),
            PayloadType::Authentication => Self::parse_authentication(input),
            PayloadType::Nonce => {
                Self::parse_raw(input).map(|(i, (data, errs))| (i, (Self::Nonce(data), errs)))
            }
            PayloadType::Notify => Self::parse_notify(input),
            PayloadType::IdentificationInitiator => Self::parse_identification_init(input),
            PayloadType::IdentificationResponder => Self::parse_identification_resp(input),
            PayloadType::Delete => Self::parse_delete(input),
            PayloadType::VendorID => {
                Self::parse_raw(input).map(|(i, (data, err))| (i, (Self::VendorId(data), err)))
            }
            PayloadType::EncryptedAndAuthenticated => Self::parse_raw(input)
                .map(|(i, (data, err))| (i, (Self::EncryptedAndAuthenticated(data), err))),
            PayloadType::Configuration => Self::parse_config(input),
            PayloadType::ExtensibleAuthenticationProtocol => Self::parse_eap(input),
            PayloadType::Unknown => {
                Self::parse_raw(input).map(|(i, (data, err))| (i, (Self::Unknown(data), err)))
            }
            PayloadType::NoNextPayload
            | PayloadType::V1Proposal
            | PayloadType::V1Transform
            | PayloadType::V1Reserved => {
                // These payloads should _never_ be seen at the top level, something is wrong
                Self::parse_raw(input).map(|(i, (data, err))| {
                    (i, (Self::Unknown(data), err | ErrorFlags::InvalidPayload))
                })
            }
            PayloadType::V1ProofOfPossession
            | PayloadType::V1NATDiscovery
            | PayloadType::V1NATOriginalAddress
            | PayloadType::V1GroupAssociationPolicy
            | PayloadType::GenericSecurePasswordMethod
            | PayloadType::GroupIdentification
            | PayloadType::GroupSecurityAssociation
            | PayloadType::KeyDownload
            | PayloadType::EncryptedAndAuthenticatedFragment
            | PayloadType::PuzzleSolution => {
                // These are valid payloads but we don't parse them
                Self::parse_raw(input).map(|(i, (data, err))| {
                    (
                        i,
                        (Self::Unknown(data), err | ErrorFlags::UnimplementedPayload),
                    )
                })
            }
        }
    }

    // Security Association - RFC2408
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !              Domain of Interpretation  (DOI)                  !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !                                                               !
    // ~                           Situation                           ~
    // !                                                               !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_v1_sa(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((
                be_u32,
                be_u32,
                map(many1(complete(Self::parse_v1_proposal)), |proposals| {
                    let (proposals, errs): (Vec<_>, Vec<_>) = proposals.into_iter().unzip();
                    let errs = ErrorFlags::flatten(&errs);
                    (proposals, errs)
                }),
            )),
            |(doi, situation, (proposals, errs))| {
                let error_flags = ErrorFlags::none() | errs;
                (
                    Self::V1SecurityAssociation {
                        doi,
                        situation,
                        proposals,
                    },
                    error_flags,
                )
            },
        )(input)
    }

    // Proposal - RFC2408
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // ! Next Payload  !   RESERVED    !         Payload Length        !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !  Proposal #   !  Protocol-Id  !    SPI Size   !# of Transforms!
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !                        SPI (variable)                         !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_v1_proposal(input: &[u8]) -> IResult<(V1Proposal, Flags<ErrorFlags>)> {
        map(
            tuple((
                be_u8,
                be_u8,
                be_u16,
                be_u8,
                be_u8,
                peek(tuple((be_u8, be_u8))),
                flat_map(tuple((be_u8, be_u8)), |(spi_size, num_transforms)| {
                    tuple((
                        take(spi_size),
                        map(
                            count(Self::parse_v1_transform, num_transforms as usize),
                            |transforms| {
                                let (transforms, errs): (Vec<_>, Vec<_>) =
                                    transforms.into_iter().unzip();
                                let errs = ErrorFlags::flatten(&errs);
                                (transforms, errs)
                            },
                        ),
                    ))
                }),
            )),
            |(
                next_payload,
                reserved,
                payload_length,
                proposal_num,
                protocol_id,
                (spi_size, num_transforms),
                (spi, (transforms, trans_errors)),
            ): (_, _, _, _, _, (_, _), (&[u8], (_, _)))| {
                let mut error_flags = ErrorFlags::none() | trans_errors;
                if reserved != 0 {
                    error_flags |= ErrorFlags::NonZeroReserved;
                }
                (
                    V1Proposal {
                        next_payload,
                        reserved,
                        payload_length,
                        proposal_num,
                        protocol_id,
                        spi_size,
                        num_transforms,
                        spi: spi.to_vec(),
                        transforms,
                    },
                    error_flags,
                )
            },
        )(input)
    }

    // Transform - RFC2408
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // ! Next Payload  !   RESERVED    !         Payload Length        !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !  Transform #  !  Transform-Id !           RESERVED2           !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !                                                               !
    // ~                        SA Attributes                          ~
    // !                                                               !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_v1_transform(input: &[u8]) -> IResult<(V1Transform, Flags<ErrorFlags>)> {
        map(
            tuple((
                be_u8,
                be_u8,
                peek(tuple((be_u16, be_u8, be_u8, be_u16))),
                flat_map(
                    tuple((be_u16, be_u8, be_u8, be_u16)),
                    |(payload_length, _, _, _)| {
                        map_parser(
                            take(payload_length.saturating_sub(8)),
                            map(many0(complete(Self::parse_attribute)), |attributes| {
                                let (attributes, errs): (Vec<_>, Vec<_>) =
                                    attributes.into_iter().unzip();
                                let errs = ErrorFlags::flatten(&errs);
                                (attributes, errs)
                            }),
                        )
                    },
                ),
            )),
            |(
                next_payload,
                reserved,
                (payload_length, transform_num, transform_id, reserved2),
                (attributes, errs),
            )| {
                let mut error_flags = ErrorFlags::none() | errs;
                if reserved != 0 || reserved2 != 0 {
                    error_flags |= ErrorFlags::NonZeroReserved;
                }
                (
                    V1Transform {
                        next_payload,
                        reserved,
                        payload_length,
                        transform_num,
                        transform_id,
                        reserved2,
                        attributes,
                    },
                    error_flags,
                )
            },
        )(input)
    }

    // Identification - RFC2408
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !   ID Type     !             DOI Specific ID Data              !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !                                                               !
    // ~                   Identification Data                         ~
    // !                                                               !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_v1_identification(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((be_u8, be_u24, rest)),
            |(id_type, doi_specific_data, id_data): (_, _, &[u8])| {
                (
                    Self::V1Identification {
                        id_type,
                        doi_specific_data,
                        id_data: id_data.to_vec(),
                    },
                    ErrorFlags::none(),
                )
            },
        )(input)
    }

    // Certificate - RFC2408
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // ! Cert Encoding !                                               !
    // +-+-+-+-+-+-+-+-+                                               !
    // ~                       Certificate Data                        ~
    // !                                                               !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_v1_certificate(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((be_u8, rest)),
            |(cert_encoding, certificate_data): (_, &[u8])| {
                (
                    Self::V1Certificate(Certificate {
                        cert_encoding,
                        certificate_data: certificate_data.to_vec(),
                    }),
                    ErrorFlags::none(),
                )
            },
        )(input)
    }

    // Certificate Request - RFC2408
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !  Cert. Type   !                                               !
    // +-+-+-+-+-+-+-+-+                                               !
    // ~                    Certificate Authority                      ~
    // !                                                               !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_v1_certificate_request(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((be_u8, rest)),
            |(cert_encoding, certification_authority): (_, &[u8])| {
                (
                    Self::V1CertificateRequest(CertificateRequest {
                        cert_encoding,
                        certification_authority: certification_authority.to_vec(),
                    }),
                    ErrorFlags::none(),
                )
            },
        )(input)
    }

    // Notification - RFC2408
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !              Domain of Interpretation  (DOI)                  !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !  Protocol-ID  !   SPI Size    !      Notify Message Type      !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !                                                               !
    // ~                Security Parameter Index (SPI)                 ~
    // !                                                               !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !                                                               !
    // ~                       Notification Data                       ~
    // !                                                               !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_v1_notification(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((
                be_u32,
                be_u8,
                peek(tuple((be_u8, be_u16))),
                flat_map(tuple((be_u8, be_u16)), |(spi_size, _)| take(spi_size)),
                rest,
            )),
            |(doi, protocol_id, (spi_size, notify_message_type), spi, notification_data): (
                _,
                _,
                _,
                _,
                &[u8],
            )| {
                (
                    Self::V1Notification {
                        doi,
                        protocol_id,
                        spi_size,
                        notify_message_type,
                        spi: spi.to_vec(),
                        notification_data: notification_data.to_vec(),
                    },
                    ErrorFlags::none(),
                )
            },
        )(input)
    }

    // Delete - RFC2408
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !              Domain of Interpretation  (DOI)                  !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !  Protocol-Id  !   SPI Size    !           # of SPIs           !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !                                                               !
    // ~               Security Parameter Index(es) (SPI)              ~
    // !                                                               !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_v1_delete(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((
                be_u32,
                be_u8,
                peek(tuple((be_u8, be_u16))),
                flat_map(tuple((be_u8, be_u16)), |(spi_size, num_spi)| {
                    count(take(spi_size), num_spi as usize)
                }),
            )),
            |(doi, protocol_id, (spi_size, num_spi), spis): (_, _, (_, _), Vec<&[u8]>)| {
                (
                    Self::V1Delete {
                        doi,
                        protocol_id,
                        spi_size,
                        num_spi,
                        spis: spis.iter().map(|slice| slice.to_vec()).collect(),
                    },
                    ErrorFlags::none(),
                )
            },
        )(input)
    }

    // SA KEK - RFC3547
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    // !    Protocol   !  SRC ID Type  !         SRC ID Port           !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    // !SRC ID Data Len!          SRC Identification Data              ~
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    // ! DST ID Type   !         DST ID Port           !DST ID Data Len!
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    // !                    DST Identification Data                    ~
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    // !                                                               !
    // ~                              SPI                              ~
    // !                                                               !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    // !         POP Algorithm         !         POP Key Length        !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    // ~                        KEK Attributes                         ~
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    fn parse_v1_sa_kek(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((
                be_u8,
                be_u8,
                be_u16,
                flat_map(be_u8, take),
                be_u8,
                be_u16,
                flat_map(be_u8, take),
                take(16usize),
                be_u16,
                be_u16,
                map(many0(complete(Self::parse_attribute)), |attributes| {
                    let (attributes, errs): (Vec<_>, Vec<_>) = attributes.into_iter().unzip();
                    let errs = ErrorFlags::flatten(&errs);
                    (attributes, errs)
                }),
            )),
            |(
                protocol,
                src_id_type,
                src_id_port,
                src_id_data,
                dst_id_type,
                dst_id_port,
                dst_id_data,
                spi,
                pop_algorithm,
                pop_key_len,
                (attributes, errs),
            ): (_, _, _, &[u8], _, _, &[u8], &[u8], _, _, (_, _))| {
                (
                    Self::V1SaKek(SaKek {
                        protocol,
                        src_id_type,
                        src_id_port,
                        src_id_data_len: src_id_data.len() as u8,
                        src_id_data: src_id_data.to_vec(),
                        dst_id_type,
                        dst_id_port,
                        dst_id_data_len: dst_id_data.len() as u8,
                        dst_id_data: dst_id_data.to_vec(),
                        spi: spi.to_vec(),
                        pop_algorithm,
                        pop_key_len,
                        attributes,
                    }),
                    ErrorFlags::none() | errs,
                )
            },
        )(input)
    }

    // SA TEK - RFC2408
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    // ! Protocol-ID   !       TEK Protocol-Specific Payload           ~
    // +-+-+-+-+-+-+-+-+                                               ~
    // ~                                                               ~
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    fn parse_v1_sa_tek(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((be_u8, rest)),
            |(protocol_id, payload): (_, &[u8])| {
                (
                    Self::V1SaTek {
                        protocol_id,
                        payload: payload.to_vec(),
                    },
                    ErrorFlags::none(),
                )
            },
        )(input)
    }

    // Key Download - RFC3547
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    // ! Number of Key Packets         !            RESERVED2          !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    // ~                    Key Packets                                ~
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    fn parse_v1_key_download(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((
                peek(tuple((be_u16, be_u16))),
                flat_map(tuple((be_u16, be_u16)), |(num_packets, _reserved)| {
                    map(
                        count(complete(Self::parse_v1_key_packet), num_packets as usize),
                        |key_packets| {
                            let (key_packets, errs): (Vec<_>, Vec<_>) =
                                key_packets.into_iter().unzip();
                            let errs = ErrorFlags::flatten(&errs);
                            (key_packets, errs)
                        },
                    )
                }),
            )),
            |((num_packets, reserved), (key_packets, errs))| {
                let mut error_flags = ErrorFlags::none() | errs;
                if reserved != 0 {
                    error_flags |= ErrorFlags::NonZeroReserved;
                }
                (
                    Self::V1KeyDownload {
                        num_packets,
                        reserved,
                        key_packets,
                    },
                    error_flags,
                )
            },
        )(input)
    }

    // Key Packet - RFC3547
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    // !   KD Type     !   RESERVED    !            KD Length          !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    // !    SPI Size   !                   SPI (variable)              ~
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    // ~                    Key Packet Attributes                      ~
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-!
    fn parse_v1_key_packet(input: &[u8]) -> IResult<(KeyPacket, Flags<ErrorFlags>)> {
        map(
            tuple((
                be_u8,
                be_u8,
                be_u16,
                flat_map(be_u8, take),
                map(many0(complete(Self::parse_attribute)), |attributes| {
                    let (attributes, errs): (Vec<_>, Vec<_>) = attributes.into_iter().unzip();
                    let errs = ErrorFlags::flatten(&errs);
                    (attributes, errs)
                }),
            )),
            |(kd_type, reserved, kd_length, spi, (attributes, errs)): (_, _, _, &[u8], (_, _))| {
                let mut error_flags = ErrorFlags::none() | errs;
                if reserved != 0 {
                    error_flags |= ErrorFlags::NonZeroReserved;
                }
                (
                    KeyPacket {
                        kd_type,
                        reserved,
                        kd_length,
                        spi_size: spi.len() as u8,
                        spi: spi.to_vec(),
                        attributes,
                    },
                    error_flags,
                )
            },
        )(input)
    }

    // Sequence Number - RFC3547
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !                      Sequence Number                          !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_v1_sequence_number(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(be_u32, |sequence| {
            (Self::V1SequenceNumber(sequence), ErrorFlags::none())
        })(input)
    }

    // Security Association - RFC7296
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                          <Proposals>                          ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_sa(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            map(many1(complete(Self::parse_proposal)), |proposals| {
                let (proposals, errs): (Vec<_>, Vec<_>) = proposals.into_iter().unzip();
                let errs = ErrorFlags::flatten(&errs);
                (proposals, errs)
            }),
            |(proposals, errs)| (Self::SecurityAssociation(proposals), errs),
        )(input)
    }

    // Proposal - RFC7296
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Last Substruc |   RESERVED    |         Proposal Length       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // ~                        SPI (variable)                         ~
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                        <Transforms>                           ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_proposal(input: &[u8]) -> IResult<(Proposal, Flags<ErrorFlags>)> {
        map(
            tuple((
                be_u8,
                be_u8,
                be_u16,
                be_u8,
                be_u8,
                peek(tuple((be_u8, be_u8))),
                flat_map(tuple((be_u8, be_u8)), |(spi_size, num_transforms)| {
                    tuple((
                        take(spi_size),
                        map(
                            count(Self::parse_transform, num_transforms as usize),
                            |transforms| {
                                let (transforms, errs): (Vec<_>, Vec<_>) =
                                    transforms.into_iter().unzip();
                                let errs = ErrorFlags::flatten(&errs);
                                (transforms, errs)
                            },
                        ),
                    ))
                }),
            )),
            |(
                last_substruc,
                reserved,
                proposal_length,
                proposal_num,
                protocol_id,
                (spi_size, num_transforms),
                (spi, (transforms, errs)),
            )| {
                let mut error_flags = ErrorFlags::none() | errs;
                if reserved != 0 {
                    error_flags |= ErrorFlags::NonZeroReserved;
                }
                (
                    Proposal {
                        last_substruc,
                        reserved,
                        proposal_length,
                        proposal_num,
                        protocol_id,
                        spi_size,
                        num_transforms,
                        spi: spi.to_vec(),
                        transforms,
                    },
                    error_flags,
                )
            },
        )(input)
    }

    // Transform - RFC7296
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Last Substruc |   RESERVED    |        Transform Length       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |Transform Type |   RESERVED    |          Transform ID         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                      Transform Attributes                     ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_transform(input: &[u8]) -> IResult<(Transform, Flags<ErrorFlags>)> {
        let mut error_flags = ErrorFlags::none();
        let (
            input,
            (last_substruc, reserved, transform_length, transform_type, reserved2, transform_id),
        ) = tuple((
            be_u8,
            be_u8,
            be_u16,
            map(be_u8, TransformType::from),
            be_u8,
            be_u16,
        ))(input)?;
        if reserved != 0 || reserved2 != 0 {
            error_flags |= ErrorFlags::NonZeroReserved;
        }
        if transform_length < 8 {
            error_flags |= ErrorFlags::InvalidLength;
        }
        let (input, attributes_input) = take(transform_length.saturating_sub(8))(input)?;
        let (_attributes_input, (attributes, errs)) =
            map(many0(complete(Self::parse_attribute)), |attributes| {
                let (attributes, errs): (Vec<_>, Vec<_>) = attributes.into_iter().unzip();
                let errs = ErrorFlags::flatten(&errs);
                (attributes, errs)
            })(attributes_input)?;
        Ok((
            input,
            (
                Transform {
                    last_substruc,
                    reserved,
                    transform_length,
                    transform_type,
                    reserved2,
                    transform_id,
                    attributes,
                },
                error_flags | errs,
            ),
        ))
    }

    // Data Attribute - RFC2408
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !A!       Attribute Type        !    AF=0  Attribute Length     !
    // !F!                             !    AF=1  Attribute Value      !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // .                   AF=0  Attribute Value                       .
    // .                   AF=1  Not Transmitted                       .
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // AF, or Attribute Format, dictates whether it is TLV (AF = 0) or TV (AF = 1) format.
    // In TLV mode, Attribute Length is present, nonzero, and measures Attribute Value.
    // In TV mode, Attribute Length is no present and Attribute Value is 2 octets.
    pub fn parse_attribute(input: &[u8]) -> IResult<(Attribute, Flags<ErrorFlags>)> {
        let (input, (att_format, att_type)) = map(
            nom::bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
                bit_take(1usize),
                bit_take(15_usize),
            ))),
            |(att_format, att_value): (u8, u16)| (AttributeFormat::from(att_format), att_value),
        )(input)?;

        let (input, (att_length, att_value)) = match att_format {
            AttributeFormat::TypeLengthValue => {
                let (input, att_value) = length_data(be_u16)(input)?;
                (input, (att_value.len() as u16, att_value))
            }
            AttributeFormat::TypeValue => {
                let (input, att_value) = take(2usize)(input)?;
                (input, (0u16, att_value))
            }
        };

        Ok((
            input,
            (
                Attribute {
                    att_format,
                    att_type,
                    att_length,
                    att_value: att_value.to_vec(),
                },
                ErrorFlags::none(),
            ),
        ))
    }

    // Key Exchange - RFC7296
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Diffie-Hellman Group Num    |           RESERVED            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                       Key Exchange Data                       ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_ke(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((be_u16, be_u16, rest)),
            |(diffie_hellman_group_num, reserved, key_exchange_data): (_, _, &[u8])| {
                let mut error_flags = ErrorFlags::none();
                if reserved != 0 {
                    error_flags |= ErrorFlags::NonZeroReserved;
                }
                (
                    Self::KeyExchange {
                        diffie_hellman_group_num,
                        reserved,
                        key_exchange_data: key_exchange_data.to_vec(),
                    },
                    error_flags,
                )
            },
        )(input)
    }

    // See parse_traffic_selector
    fn parse_traffic_selector_init(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(Self::parse_traffic_selector, |(ts, err)| {
            (Self::TrafficSelectorInitiator(ts), err)
        })(input)
    }

    // See parse_traffic_selector
    fn parse_traffic_selector_resp(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(Self::parse_traffic_selector, |(ts, err)| {
            (Self::TrafficSelectorResponder(ts), err)
        })(input)
    }

    // Traffic Selector Init/Resp - RFC7296
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Number of TSs |                 RESERVED                      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                       <Traffic Selectors>                     ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_traffic_selector(input: &[u8]) -> IResult<(TrafficSelector, Flags<ErrorFlags>)> {
        map(
            tuple((
                peek(tuple((be_u8, be_u24))),
                flat_map(tuple((be_u8, be_u24)), |(number_ts, _): (u8, u32)| {
                    map(
                        count(Self::parse_traffic_selector_body, number_ts.into()),
                        |traffic_selectors| {
                            let (traffic_selectors, errs): (Vec<_>, Vec<_>) =
                                traffic_selectors.into_iter().unzip();
                            let errs = ErrorFlags::flatten(&errs);
                            (traffic_selectors, errs)
                        },
                    )
                }),
            )),
            |((number_ts, reserved), (traffic_selectors, errs))| {
                (
                    TrafficSelector {
                        number_ts,
                        reserved,
                        traffic_selectors,
                    },
                    errs,
                )
            },
        )(input)
    }

    // Traffic Selector - RFC7296
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   TS Type     |IP Protocol ID*|       Selector Length         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |           Start Port*         |           End Port*           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                         Starting Address*                     ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                         Ending Address*                       ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // Note: Fields marked with an asterisk (*) depend on TS Tyoe. Currently
    // handled ones are 7 (IPv4 addresses), 8 (IPv6 addresses), and 9 (Fibre).
    pub fn parse_traffic_selector_body(
        input: &[u8],
    ) -> IResult<(TrafficSelectorBody, Flags<ErrorFlags>)> {
        let mut error_flags = ErrorFlags::none();
        let (input, (ts_type, ip_protocol_id, selector_length)) =
            tuple((be_u8, be_u8, be_u16))(input)?;
        if selector_length < 4 {
            error_flags |= ErrorFlags::InvalidLength;
        }
        let (input, selector_input) = take(selector_length.saturating_sub(4))(input)?;

        let (_selector_input, (address, errs)) = match ts_type {
            7 => map(
                tuple((be_u16, be_u16, be_u32, be_u32)),
                |(start_port, end_port, starting_address, ending_address)| {
                    (
                        Address::Ipv4(AddressV4 {
                            start_port,
                            end_port,
                            starting_address: std::net::Ipv4Addr::from(starting_address),
                            ending_address: std::net::Ipv4Addr::from(ending_address),
                        }),
                        ErrorFlags::none(),
                    )
                },
            )(selector_input)?,
            8 => map(
                tuple((be_u16, be_u16, take(16usize), take(16usize))),
                |(start_port, end_port, starting_address, ending_address): (_, _, &[u8], &[u8])| {
                    // SAFETY:
                    // The two arrays we slice are guaranteed to be exactly 16 bytes
                    let starting_address: [u8; 16] = starting_address[0..16].try_into().unwrap();
                    let ending_address: [u8; 16] = ending_address[0..16].try_into().unwrap();
                    (
                        Address::Ipv6(AddressV6 {
                            start_port,
                            end_port,
                            starting_address: std::net::Ipv6Addr::from(starting_address),
                            ending_address: std::net::Ipv6Addr::from(ending_address),
                        }),
                        ErrorFlags::none(),
                    )
                },
            )(selector_input)?,
            9 => map(
                tuple((be_u8, be_u24, be_u8, be_u24, be_u8, be_u8, be_u8, be_u8)),
                |(
                    reserved,
                    starting_address,
                    reserved2,
                    ending_address,
                    starting_r_ctl,
                    ending_r_ctl,
                    starting_type,
                    ending_type,
                )| {
                    let mut error_flags = ErrorFlags::none();
                    if reserved != 0 || reserved2 != 0 {
                        error_flags |= ErrorFlags::NonZeroReserved;
                    }
                    (
                        Address::Fibre(Fibre {
                            reserved,
                            starting_address,
                            reserved2,
                            ending_address,
                            starting_r_ctl,
                            ending_r_ctl,
                            starting_type,
                            ending_type,
                        }),
                        error_flags,
                    )
                },
            )(selector_input)?,
            _ => map(rest, |data: &[u8]| {
                (Address::Unknown(data.to_vec()), ErrorFlags::none())
            })(selector_input)?,
        };
        error_flags |= errs;

        Ok((
            input,
            (
                TrafficSelectorBody {
                    ts_type,
                    ip_protocol_id,
                    selector_length,
                    address,
                },
                error_flags,
            ),
        ))
    }

    // Parse Certificate
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Cert Encoding |                                               |
    // +-+-+-+-+-+-+-+-+                                               |
    // ~                       Certificate Data                        ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_certificate(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((be_u8, rest)),
            |(cert_encoding, certificate_data): (_, &[u8])| {
                (
                    Self::Certificate(Certificate {
                        cert_encoding,
                        certificate_data: certificate_data.to_vec(),
                    }),
                    ErrorFlags::none(),
                )
            },
        )(input)
    }

    // Certificate Request
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Cert Encoding |                                               |
    // +-+-+-+-+-+-+-+-+                                               |
    // ~                    Certification Authority                    ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_certificate_request(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((be_u8, rest)),
            |(cert_encoding, certification_authority): (_, &[u8])| {
                (
                    Self::CertificateRequest(CertificateRequest {
                        cert_encoding,
                        certification_authority: certification_authority.to_vec(),
                    }),
                    ErrorFlags::none(),
                )
            },
        )(input)
    }

    // Authentication
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Auth Method   |                RESERVED                       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                      Authentication Data                      ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_authentication(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((be_u8, be_u24, rest)),
            |(auth_method, reserved, authentication_data): (_, _, &[u8])| {
                let mut error_flags = ErrorFlags::none();
                if reserved != 0 {
                    error_flags |= ErrorFlags::NonZeroReserved;
                }
                (
                    Self::Authentication {
                        auth_method,
                        reserved,
                        authentication_data: authentication_data.to_vec(),
                    },
                    error_flags,
                )
            },
        )(input)
    }

    // Simply takes the rest of the buffer, clones it into a vec and returns it.
    // Used for several types which are simple data buffers with no other data.
    fn parse_raw(input: &[u8]) -> IResult<(Vec<u8>, Flags<ErrorFlags>)> {
        rest(input).map(|(i, data)| (i, (data.to_vec(), ErrorFlags::none())))
    }

    // Notify - RFC7296
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |  Protocol ID  |   SPI Size    |      Notify Message Type      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                Security Parameter Index (SPI)                 ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                       Notification Data                       ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_notify(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((
                be_u8,
                peek(tuple((be_u8, be_u16))),
                flat_map(tuple((be_u8, be_u16)), |(spi_size, _type)| take(spi_size)),
                rest,
            )),
            |(protocol_id, (spi_size, notify_message_type), spi, notification_data): (
                _,
                (_, _),
                &[u8],
                &[u8],
            )| {
                (
                    Self::Notify {
                        protocol_id,
                        spi_size,
                        notify_message_type,
                        spi: spi.to_vec(),
                        notification_data: notification_data.to_vec(),
                    },
                    ErrorFlags::none(),
                )
            },
        )(input)
    }

    // See parse_identification
    fn parse_identification_init(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(Self::parse_identification, |(identification, err)| {
            (Self::IdentificationInit(identification), err)
        })(input)
    }

    fn parse_identification_resp(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(Self::parse_identification, |(identification, err)| {
            (Self::IdentificationResp(identification), err)
        })(input)
    }

    // Identification - RFC7296
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   ID Type     |                 RESERVED                      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                   Identification Data                         ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_identification(input: &[u8]) -> IResult<(Identification, Flags<ErrorFlags>)> {
        map(
            tuple((be_u8, be_u24, rest)),
            |(id_type, reserved, identification_data): (_, _, &[u8])| {
                let mut error_flags = ErrorFlags::none();
                if reserved != 0 {
                    error_flags |= ErrorFlags::NonZeroReserved;
                }
                (
                    Identification {
                        id_type,
                        reserved,
                        identification_data: identification_data.to_vec(),
                    },
                    error_flags,
                )
            },
        )(input)
    }

    // Delete - RFC7296
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Protocol ID   |   SPI Size    |          Num of SPIs          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~               Security Parameter Index(es) (SPI)              ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_delete(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((
                be_u8,
                peek(tuple((be_u8, be_u16))),
                flat_map(tuple((be_u8, be_u16)), |(spi_size, num_spi)| {
                    count(take(spi_size), num_spi as usize)
                }),
            )),
            |(protocol_id, (spi_size, num_spi), spis): (_, (_, _), Vec<&[u8]>)| {
                (
                    Self::Delete {
                        protocol_id,
                        spi_size,
                        num_spi,
                        spis: spis.iter().map(|slice| slice.to_vec()).collect(),
                    },
                    ErrorFlags::none(),
                )
            },
        )(input)
    }

    // Config - RFC7296
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Protocol ID   |   SPI Size    |          Num of SPIs          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~               Security Parameter Index(es) (SPI)              ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_config(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((
                be_u8,
                be_u24,
                map(many0(complete(Self::parse_attribute)), |attributes| {
                    let (attributes, errs): (Vec<_>, Vec<_>) = attributes.into_iter().unzip();
                    let errs = ErrorFlags::flatten(&errs);
                    (attributes, errs)
                }),
            )),
            |(cfg_type, reserved, (attributes, errs))| {
                let mut error_flags = ErrorFlags::none() | errs;
                if reserved != 0 {
                    error_flags |= ErrorFlags::NonZeroReserved;
                }
                (
                    Self::Configuration {
                        cfg_type,
                        reserved,
                        attributes,
                    },
                    error_flags,
                )
            },
        )(input)
    }

    // Extensible Authentication Protocol (EAP) - RFC7296
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Code      | Identifier    |           Length              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      | Type_Data...                                  ~
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse_eap(input: &[u8]) -> IResult<(Self, Flags<ErrorFlags>)> {
        map(
            tuple((be_u8, be_u8, be_u16, be_u8, rest)),
            |(code, identifier, length, r#type, type_data): (_, _, _, _, &[u8])| {
                (
                    Self::ExtensibleAuthenticationProtocol {
                        code,
                        identifier,
                        length,
                        r#type,
                        type_data: type_data.to_vec(),
                    },
                    ErrorFlags::none(),
                )
            },
        )(input)
    }
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct V1Proposal {
    pub next_payload: u8,
    pub reserved: u8,
    pub payload_length: u16,
    pub proposal_num: u8,
    pub protocol_id: u8,
    pub spi_size: u8,
    pub num_transforms: u8,
    pub spi: Vec<u8>,
    pub transforms: Vec<V1Transform>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct V1Transform {
    pub next_payload: u8,
    pub reserved: u8,
    pub payload_length: u16,
    pub transform_num: u8,
    pub transform_id: u8,
    pub reserved2: u16,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SaKek {
    pub protocol: u8,
    pub src_id_type: u8,
    pub src_id_port: u16,
    pub src_id_data_len: u8,
    pub src_id_data: Vec<u8>,
    pub dst_id_type: u8,
    pub dst_id_port: u16,
    pub dst_id_data_len: u8,
    pub dst_id_data: Vec<u8>,
    pub spi: Vec<u8>,
    pub pop_algorithm: u16,
    pub pop_key_len: u16,
    pub attributes: Vec<Attribute>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct KeyPacket {
    pub kd_type: u8,
    pub reserved: u8,
    pub kd_length: u16,
    pub spi_size: u8,
    pub spi: Vec<u8>,
    pub attributes: Vec<Attribute>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Proposal {
    pub last_substruc: u8,
    pub reserved: u8,
    pub proposal_length: u16,
    pub proposal_num: u8,
    pub protocol_id: u8,
    pub spi_size: u8,
    pub num_transforms: u8,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Transform {
    pub last_substruc: u8,
    pub reserved: u8,
    pub transform_length: u16,
    pub transform_type: TransformType,
    pub reserved2: u8,
    pub transform_id: u16,
    pub attributes: Vec<Attribute>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, FromPrimitive, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum TransformType {
    Reserved = 0,
    EncryptionAlgorithm = 1,
    PseudoRandomFunction = 2,
    IntegrityCheck = 3,
    DiffieHellmanGroup = 4,
    ExtendedSequenceNumbers = 5,
    AdditionalKeyExchange1 = 6,
    AdditionalKeyExchange2 = 7,
    AdditionalKeyExchange3 = 8,
    AdditionalKeyExchange4 = 9,
    AdditionalKeyExchange5 = 10,
    AdditionalKeyExchange6 = 11,
    AdditionalKeyExchange7 = 12,
    // 13..=240 are Unassigned and 241..=255 are Private but num_enum
    // does not accept ranges and hand-writing so many variants is verbose.
    #[num_enum(default)]
    Unassigned,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Attribute {
    pub att_format: AttributeFormat,
    pub att_type: u16,
    pub att_length: u16,
    pub att_value: Vec<u8>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq, FromPrimitive)]
#[repr(u8)]
pub enum AttributeFormat {
    #[num_enum(default)]
    TypeLengthValue = 0,
    TypeValue = 1,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct TrafficSelector {
    pub number_ts: u8,
    pub reserved: u32, // 24 bits
    pub traffic_selectors: Vec<TrafficSelectorBody>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct TrafficSelectorBody {
    pub ts_type: u8,
    pub ip_protocol_id: u8,
    pub selector_length: u16,
    pub address: Address,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub enum Address {
    Ipv4(AddressV4),
    Ipv6(AddressV6),
    Fibre(Fibre),
    Unknown(Vec<u8>),
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct AddressV4 {
    pub start_port: u16,
    pub end_port: u16,
    pub starting_address: std::net::Ipv4Addr,
    pub ending_address: std::net::Ipv4Addr,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct AddressV6 {
    pub start_port: u16,
    pub end_port: u16,
    pub starting_address: std::net::Ipv6Addr,
    pub ending_address: std::net::Ipv6Addr,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Fibre {
    pub reserved: u8,
    pub starting_address: u32, // Actually 24 bits left-padded to 32
    pub reserved2: u8,
    pub ending_address: u32,
    pub starting_r_ctl: u8,
    pub ending_r_ctl: u8,
    pub starting_type: u8,
    pub ending_type: u8,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Certificate {
    pub cert_encoding: u8,
    pub certificate_data: Vec<u8>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct CertificateRequest {
    pub cert_encoding: u8,
    pub certification_authority: Vec<u8>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Identification {
    pub id_type: u8,
    pub reserved: u32, // 24 bits
    pub identification_data: Vec<u8>,
}
