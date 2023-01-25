use crate::{flags_mask, ErrorFlags, PayloadType};

use sawp::error::Result;
use sawp_flags::{Flag, Flags};

#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

use nom::combinator::{map, verify};
use nom::number::streaming::{be_u32, be_u64, be_u8};
use nom::sequence::tuple;

use num_enum::FromPrimitive;

/// Length of an IKE header
pub const HEADER_LEN: u32 = 28;

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, FromPrimitive, PartialEq, Eq, Copy, Clone)]
#[repr(u8)]
pub enum ExchangeType {
    None = 0,
    Base = 1,
    IdentityProtection = 2,
    AuthenticationOnly = 3,
    Aggressive = 4,
    InformationalV1 = 5,
    IkeSaInit = 34,
    IkeAuth = 35,
    CreateChildSa = 36,
    Informational = 37,
    IkeSessionResume = 38,
    GsaAuth = 39,
    GsaRegistration = 40,
    GsaRekey = 41,
    IkeIntermediate = 43,
    IkeFollowupKe = 44,
    #[num_enum(default)]
    Unknown,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq)]
pub struct Header {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub raw_next_payload: u8,
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub next_payload: PayloadType,
    pub version: u8,
    pub major_version: u8,
    pub minor_version: u8,
    pub raw_exchange_type: u8,
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub exchange_type: ExchangeType,
    pub flags: u8,
    pub message_id: u32,
    pub length: u32,
}

impl Header {
    pub const MAJOR_VERSION_MASK: u8 = 0xF0;
    pub const MINOR_VERSION_MASK: u8 = 0x0F;

    // V1 Header - RFC2408
    //                     1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !                          Initiator                            !
    // !                            Cookie                             !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !                          Responder                            !
    // !                            Cookie                             !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !  Next Payload ! MjVer ! MnVer ! Exchange Type !     Flags     !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !                          Message ID                           !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // !                            Length                             !
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // V2 Header - RFC7296
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                       IKE SA Initiator's SPI                  |
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                       IKE SA Responder's SPI                  |
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                          Message ID                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                            Length                             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #[allow(clippy::type_complexity)]
    pub fn parse(input: &[u8]) -> Result<(&[u8], (Self, Flags<ErrorFlags>))> {
        let mut error_flags = ErrorFlags::none();

        let (
            input,
            (
                initiator_spi,
                responder_spi,
                (raw_next_payload, next_payload),
                (version, (major_version, minor_version)),
            ),
        ) = tuple((
            be_u64,
            be_u64,
            map(be_u8, |np| (np, PayloadType::from(np))),
            verify(
                map(be_u8, |version| (version, Self::split_version(version))),
                |(_, (major, _))| (1..=2).contains(major),
            ),
        ))(input)?;

        let next_payload = if (major_version == 1 && !next_payload.is_v1())
            || (major_version == 2 && !next_payload.is_v2())
        {
            PayloadType::Unknown
        } else {
            next_payload
        };
        if next_payload == PayloadType::Unknown {
            error_flags |= ErrorFlags::UnknownPayload;
        }

        let (input, ((raw_exchange_type, exchange_type), flags, message_id, length)) =
            tuple((
                map(be_u8, |et| (et, ExchangeType::from(et))),
                be_u8,
                be_u32,
                verify(be_u32, |length| *length >= HEADER_LEN),
            ))(input)?;
        if exchange_type == ExchangeType::Unknown {
            error_flags |= ErrorFlags::UnknownExchange;
        }
        let wrapped_flags = Flags::<flags_mask>::from_bits(flags);

        if exchange_type == ExchangeType::IkeSaInit
            && wrapped_flags.intersects(flags_mask::INITIATOR_FLAG)
        {
            // message_id must be zero in an initiator request
            if message_id != 0 {
                error_flags |= ErrorFlags::NonZeroMessageIdInInit;
            }
            // responder_spi must be zero in an initiator request
            if wrapped_flags.intersects(flags_mask::INITIATOR_FLAG) && responder_spi != 0 {
                error_flags |= ErrorFlags::NonZeroResponderSpiInInit;
            }
        }

        if wrapped_flags.intersects(flags_mask::RESPONSE_FLAG) && responder_spi == 0 {
            error_flags |= ErrorFlags::ZeroResponderSpiInResponse;
        }

        Ok((
            input,
            (
                Self {
                    initiator_spi,
                    responder_spi,
                    raw_next_payload,
                    next_payload,
                    version,
                    major_version,
                    minor_version,
                    raw_exchange_type,
                    exchange_type,
                    flags,
                    message_id,
                    length,
                },
                error_flags,
            ),
        ))
    }

    fn major_version(version: u8) -> u8 {
        (version & Self::MAJOR_VERSION_MASK)
            .checked_shr(4)
            .unwrap_or(0)
    }

    fn minor_version(version: u8) -> u8 {
        version & Self::MINOR_VERSION_MASK
    }

    fn split_version(version: u8) -> (u8, u8) {
        (Self::major_version(version), Self::minor_version(version))
    }
}
