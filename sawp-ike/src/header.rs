use crate::{ErrorFlags, PayloadType};

use sawp::error::Result;
use sawp_flags::{BitFlags, Flag, Flags};

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
    QuickMode = 32,
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

/// Flags that can be set for IKEv1 and IKEv2
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, BitFlags)]
pub enum IkeFlags {
    /// Body is encrypted
    ENCRYPTED = 0b0000_0001,
    /// Signal for Key Exchange synchronization
    COMMIT = 0b0000_0010,
    /// Authenticated but not Encrypted
    AUTHENTICATION = 0b0000_0100,
    /// Sender is the original initiator
    INITIATOR = 0b0000_1000,
    /// Version upgrade available from sender
    VERSION = 0b0001_0000,
    /// Message is a response to a message containing the same Message ID
    RESPONSE = 0b0010_0000,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Header {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub next_payload: PayloadType,
    pub version: u8,
    pub major_version: u8,
    pub minor_version: u8,
    pub exchange_type: ExchangeType,
    #[cfg_attr(feature = "ffi", sawp_ffi(flag = "u8"))]
    pub flags: Flags<IkeFlags>,
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
            (initiator_spi, responder_spi, next_payload, (version, (major_version, minor_version))),
        ) = tuple((
            be_u64,
            be_u64,
            map(be_u8, PayloadType::from),
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

        let (input, (exchange_type, flags, message_id, length)) = tuple((
            map(be_u8, ExchangeType::from),
            map(be_u8, Flags::<IkeFlags>::from_bits),
            be_u32,
            verify(be_u32, |length| *length >= HEADER_LEN),
        ))(input)?;
        if exchange_type == ExchangeType::Unknown {
            error_flags |= ErrorFlags::UnknownExchange;
        }

        let ikev1_flags = IkeFlags::ENCRYPTED | IkeFlags::COMMIT | IkeFlags::AUTHENTICATION;
        let ikev2_flags = IkeFlags::INITIATOR | IkeFlags::VERSION | IkeFlags::RESPONSE;
        if flags.intersects(ikev1_flags) && flags.intersects(ikev2_flags) {
            error_flags |= ErrorFlags::InvalidFlags;
        }

        if exchange_type == ExchangeType::IkeSaInit && flags.intersects(IkeFlags::INITIATOR) {
            // message_id must be zero in an initiator request
            if message_id != 0 {
                error_flags |= ErrorFlags::NonZeroMessageIdInInit;
            }
            // responder_spi must be zero in an initiator request
            if flags.intersects(IkeFlags::INITIATOR) && responder_spi != 0 {
                error_flags |= ErrorFlags::NonZeroResponderSpiInInit;
            }
        }

        if flags.intersects(IkeFlags::RESPONSE) && responder_spi == 0 {
            error_flags |= ErrorFlags::ZeroResponderSpiInResponse;
        }

        Ok((
            input,
            (
                Self {
                    initiator_spi,
                    responder_spi,
                    next_payload,
                    version,
                    major_version,
                    minor_version,
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
