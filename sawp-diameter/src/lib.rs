//! Protocol References:
//!     https://tools.ietf.org/html/rfc6733

#![allow(clippy::upper_case_acronyms)]

use sawp::error::Result;
use sawp::parser::{Direction, Parse};
use sawp::probe::Probe;
use sawp::protocol::Protocol;

use nom::bytes::streaming::tag;
use nom::bytes::streaming::take;
use nom::combinator;
use nom::error::ErrorKind;
use nom::multi::many0;
use nom::number::streaming::{be_u24, be_u32, be_u64, be_u8};
use nom::IResult;

use num_enum::TryFromPrimitive;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;

#[derive(Debug)]
pub struct Diameter {}

#[derive(Debug, PartialEq)]
pub struct Header {
    version: u8,
    length: u32, // Actually u24
    flags: u8,
    code: u32, // Actually u24
    app_id: u32,
    hop_id: u32,
    end_id: u32,
}

/// AVP Attribute Names as stated in the [protocol reference](https://tools.ietf.org/html/rfc6733#section-4.5)
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum AttributeCode {
    Unknown = 0,
    AcctInterimInterval = 85,
    AccountingRealtimeRequired = 483,
    AcctMultiSessionId = 50,
    AccountingRecordNumber = 485,
    AccountingRecordType = 480,
    AcctSessionId = 44,
    AccountingSubSessionId = 287,
    AcctApplicationId = 259,
    AuthApplicationId = 258,
    AuthRequestType = 274,
    AuthorizationLifetime = 291,
    AuthGracePeriod = 276,
    AuthSessionState = 277,
    ReAuthRequestType = 285,
    Class = 25,
    DestinationHost = 293,
    DestinationRealm = 235,
    DisconnectCause = 273,
    ErrorMessage = 281,
    ErrorReportingHost = 294,
    EventTimestamp = 55,
    ExperimentalResult = 297,
    ExperimentalResultCode = 298,
    FailedAVP = 279,
    FirmwareRevision = 267,
    HostIPAddress = 257,
    InbandSecurityId = 299,
    MultiRoundTimeOut = 272,
    OriginHost = 264,
    OriginRealm = 296,
    OriginStateId = 278,
    ProductName = 269,
    ProxyHost = 280,
    ProxyInfo = 284,
    ProxyState = 33,
    RedirectHost = 292,
    RedirectHostUsage = 261,
    RedirectMaxCacheTime = 262,
    ResultCode = 268,
    RouteRecord = 282,
    SessionId = 263,
    SessionTimeout = 27,
    SessionBinding = 270,
    SessionServerFailover = 271,
    SupportedVendorId = 265,
    TerminationCause = 295,
    UserName = 1,
    VendorId = 266,
    VendorSpecificApplicationId = 260,
}

#[derive(Debug, PartialEq)]
pub struct Attribute {
    /// Value of the code in AVP header
    raw: u32,
    /// Attribute name associated with raw value
    code: AttributeCode,
}

impl Attribute {
    pub fn new(val: u32) -> Self {
        Attribute {
            raw: val,
            code: AttributeCode::try_from(val).unwrap_or(AttributeCode::Unknown),
        }
    }
}

/// AVP Data Format as specified in the [protocol reference](https://tools.ietf.org/html/rfc6733#section-4.2)
#[derive(Debug, PartialEq)]
pub enum Value {
    Unhandled(Vec<u8>),
    OctetString(Vec<u8>),
    Integer32(i32),
    Integer64(i64),
    Unsigned32(u32),
    Unsigned64(u64),
    Float32(f32),
    Float64(f64),
    Grouped(Vec<AVP>),
    Enumerated(u32),
    UTF8String(String),
    DiameterIdentity(String),
    DiameterURI(String),
    Address(std::net::IpAddr),
    Time(u32),
}

impl Value {
    pub fn new<'a>(code: &AttributeCode, data: &'a [u8]) -> IResult<&'a [u8], (Self, ErrorFlags)> {
        match code {
            AttributeCode::AcctSessionId | AttributeCode::ProxyState => {
                Ok((&[], (Value::OctetString(data.into()), ErrorFlags::NONE)))
            }
            AttributeCode::AcctInterimInterval
            | AttributeCode::AccountingRecordNumber
            | AttributeCode::AcctApplicationId
            | AttributeCode::AuthApplicationId
            | AttributeCode::AuthorizationLifetime
            | AttributeCode::AuthGracePeriod
            | AttributeCode::ExperimentalResultCode
            | AttributeCode::FirmwareRevision
            | AttributeCode::InbandSecurityId
            | AttributeCode::MultiRoundTimeOut
            | AttributeCode::OriginStateId
            | AttributeCode::RedirectMaxCacheTime
            | AttributeCode::ResultCode
            | AttributeCode::SessionTimeout
            | AttributeCode::SessionBinding
            | AttributeCode::SupportedVendorId
            | AttributeCode::VendorId => {
                let (input, val) = be_u32(data)?;
                Ok((input, (Value::Unsigned32(val), ErrorFlags::NONE)))
            }
            AttributeCode::AccountingSubSessionId => {
                let (input, val) = be_u64(data)?;
                Ok((input, (Value::Unsigned64(val), ErrorFlags::NONE)))
            }
            AttributeCode::AccountingRealtimeRequired
            | AttributeCode::AccountingRecordType
            | AttributeCode::AuthRequestType
            | AttributeCode::AuthSessionState
            | AttributeCode::ReAuthRequestType
            | AttributeCode::DisconnectCause
            | AttributeCode::RedirectHostUsage
            | AttributeCode::SessionServerFailover
            | AttributeCode::TerminationCause => {
                let (input, val) = be_u32(data)?;
                Ok((input, (Value::Enumerated(val), ErrorFlags::NONE)))
            }
            AttributeCode::ExperimentalResult
            | AttributeCode::FailedAVP
            | AttributeCode::ProxyInfo
            | AttributeCode::VendorSpecificApplicationId => {
                let (input, (avps, error_flags)) = parse_avps(data)?;
                Ok((input, (Value::Grouped(avps), error_flags)))
            }
            AttributeCode::AcctMultiSessionId
            | AttributeCode::Class
            | AttributeCode::ErrorMessage
            | AttributeCode::ProductName
            | AttributeCode::SessionId
            | AttributeCode::UserName => match String::from_utf8(data.to_vec()) {
                Ok(string) => Ok((&[], (Value::UTF8String(string), ErrorFlags::NONE))),
                Err(_) => Ok((&[], (Value::Unhandled(data.into()), ErrorFlags::DATA_VALUE))),
            },
            AttributeCode::DestinationHost
            | AttributeCode::DestinationRealm
            | AttributeCode::ErrorReportingHost
            | AttributeCode::OriginHost
            | AttributeCode::OriginRealm
            | AttributeCode::ProxyHost
            | AttributeCode::RouteRecord => match String::from_utf8(data.to_vec()) {
                Ok(string) => Ok((&[], (Value::DiameterIdentity(string), ErrorFlags::NONE))),
                Err(_) => Ok((&[], (Value::Unhandled(data.into()), ErrorFlags::DATA_VALUE))),
            },
            AttributeCode::RedirectHost => match String::from_utf8(data.to_vec()) {
                Ok(string) => Ok((&[], (Value::DiameterURI(string), ErrorFlags::NONE))),
                Err(_) => Ok((&[], (Value::Unhandled(data.into()), ErrorFlags::DATA_VALUE))),
            },
            AttributeCode::HostIPAddress => match data.len() {
                4 => Ok((
                    &[],
                    (
                        // unwrap shouldn't panic, since we check length
                        Value::Address(IpAddr::V4(Ipv4Addr::from(
                            <[u8; 4]>::try_from(data).unwrap(),
                        ))),
                        ErrorFlags::NONE,
                    ),
                )),
                16 => Ok((
                    &[],
                    (
                        // unwrap shouldn't panic, since we check length
                        Value::Address(IpAddr::V6(Ipv6Addr::from(
                            <[u8; 16]>::try_from(data).unwrap(),
                        ))),
                        ErrorFlags::NONE,
                    ),
                )),
                _ => Ok((
                    &[],
                    (Value::Unhandled(data.into()), ErrorFlags::DATA_LENGTH),
                )),
            },
            AttributeCode::EventTimestamp => {
                let (input, seconds) = be_u32(data)?;
                Ok((input, (Value::Time(seconds), ErrorFlags::NONE)))
            }
            _ => Ok((&[], (Value::Unhandled(data.into()), ErrorFlags::NONE))),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct AVP {
    attribute: Attribute,
    flags: u8,
    length: u32, // Actually u24
    vendor_id: Option<u32>,
    value: Value,
    padding: Vec<u8>,
}

bitflags! {
    /// Flags identify messages which parse successfully
    /// but contain invalid data. The caller can use the message's
    /// error flags to see if and what errors were in the
    /// pack of bytes and take action using this information.
    pub struct ErrorFlags: u8 {
        const NONE = 0b0000_0000;
        const DATA_VALUE = 0b0000_0001;
        const DATA_LENGTH = 0b0000_0010;
        const NON_ZERO_RESERVED = 0b0000_0100;
        const NON_ZERO_PADDING = 0b0000_1000;
    }
}

#[derive(Debug, PartialEq)]
pub struct Message {
    pub header: Header,
    pub avps: Vec<AVP>,
    pub error_flags: ErrorFlags,
}

/// Create a parser to read diameter length and ensure input is long enough
/// # Arguments
/// * `read` - How many bytes of length have already been read
///
fn length(read: usize) -> impl Fn(&[u8]) -> IResult<&[u8], u32> {
    move |input: &[u8]| {
        let (input, length) = be_u24(input)?;
        let len = length as usize;
        if len < read {
            Err(nom::Err::Error((input, ErrorKind::LengthValue)))
        } else if len > (input.len() + read) {
            Err(nom::Err::Incomplete(nom::Needed::Size(
                len - (input.len() + read),
            )))
        } else {
            Ok((input, length))
        }
    }
}

impl Header {
    const SIZE: usize = 20;
    // Number of bytes included in length that are before and
    // including the length field
    const PRE_LENGTH_SIZE: usize = 4;

    // Flags
    pub const REQUEST_FLAG: u8 = 0b1000_0000;
    pub const PROXIABLE_FLAG: u8 = 0b0100_0000;
    pub const ERROR_FLAG: u8 = 0b0010_0000;
    pub const POTENTIALLY_RETRANSMITTED_FLAG: u8 = 0b0001_0000;
    pub const RESERVED_MASK: u8 = 0b0000_1111;

    fn reserved_set(flags: u8) -> bool {
        flags & Self::RESERVED_MASK != 0
    }

    ///  If set, the message is a request.  If cleared, the message is
    /// an answer.
    pub fn is_request(&self) -> bool {
        self.flags & Self::REQUEST_FLAG != 0
    }

    /// If set, the message MAY be proxied, relayed, or redirected.  If
    /// cleared, the message MUST be locally processed.
    pub fn is_proxiable(&self) -> bool {
        self.flags & Self::PROXIABLE_FLAG != 0
    }

    /// If set, the message contains a protocol error, and the message
    /// will not conform to the CCF described for this command.
    /// Messages with the 'E' bit set are commonly referred to as error
    /// messages.  This bit MUST NOT be set in request messages
    pub fn is_error(&self) -> bool {
        self.flags & Self::ERROR_FLAG != 0
    }

    /// This flag is set after a link failover procedure, to aid the
    /// removal of duplicate requests.  It is set when resending
    /// requests not yet acknowledged, as an indication of a possible
    /// duplicate due to a link failure.
    pub fn is_potentially_retransmitted(&self) -> bool {
        self.flags & Self::POTENTIALLY_RETRANSMITTED_FLAG != 0
    }

    /// These flag bits are reserved for future use; they MUST be set
    /// to zero and ignored by the receiver.
    pub fn get_reserved(&self) -> u8 {
        self.flags & Self::RESERVED_MASK
    }

    /// Length of AVPs
    pub fn length(&self) -> usize {
        (self.length as usize) - Self::SIZE
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], (Self, ErrorFlags)> {
        let mut error_flags = ErrorFlags::NONE;
        let (input, version) = tag(&[1u8])(input)?;
        let (input, length) = length(Self::PRE_LENGTH_SIZE)(input)?;
        if (length as usize) < Self::SIZE {
            return Err(nom::Err::Error((input, ErrorKind::LengthValue)));
        }
        let (input, flags) = be_u8(input)?;
        if Self::reserved_set(flags) {
            error_flags |= ErrorFlags::NON_ZERO_RESERVED;
        }
        let (input, code) = be_u24(input)?;
        let (input, app_id) = be_u32(input)?;
        let (input, hop_id) = be_u32(input)?;
        let (input, end_id) = be_u32(input)?;

        Ok((
            input,
            (
                Self {
                    version: version[0],
                    length,
                    flags,
                    code,
                    app_id,
                    hop_id,
                    end_id,
                },
                error_flags,
            ),
        ))
    }
}

impl AVP {
    // Number of bytes included in length that are before and
    // including the length field
    const PRE_LENGTH_SIZE: usize = 8;

    // Flags
    pub const VENDOR_SPECIFIC_FLAG: u8 = 0b1000_0000;
    pub const MANDATORY_FLAG: u8 = 0b0100_0000;
    pub const PROTECTED_FLAG: u8 = 0b0010_0000;
    pub const RESERVED_MASK: u8 = 0b0001_1111;

    fn vendor_specific_flag(flags: u8) -> bool {
        flags & Self::VENDOR_SPECIFIC_FLAG != 0
    }

    fn reserved_set(flags: u8) -> bool {
        flags & Self::RESERVED_MASK != 0
    }

    fn padding(length: usize) -> usize {
        match length % 4 {
            0 => 0,
            n => 4 - n,
        }
    }

    /// The 'V' bit, known as the Vendor-Specific bit, indicates whether
    /// the optional Vendor-ID field is present in the AVP header.  When
    /// set, the AVP Code belongs to the specific vendor code address
    /// space.
    pub fn is_vendor_specific(&self) -> bool {
        Self::vendor_specific_flag(self.flags)
    }

    /// The 'M' bit, known as the Mandatory bit, indicates whether the
    /// receiver of the AVP MUST parse and understand the semantics of the
    /// AVP including its content.
    pub fn is_mandatory(&self) -> bool {
        self.flags & Self::MANDATORY_FLAG != 0
    }

    /// The 'P' bit, known as the Protected bit, has been reserved for
    /// future usage of end-to-end security
    pub fn is_protected(&self) -> bool {
        self.flags & Self::PROTECTED_FLAG != 0
    }

    /// The sender of the AVP MUST set 'R' (reserved) bits to 0 and the
    /// receiver SHOULD ignore all 'R' (reserved) bits.
    pub fn get_reserved(&self) -> u8 {
        self.flags & Self::RESERVED_MASK
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], (Self, ErrorFlags)> {
        let mut error_flags = ErrorFlags::NONE;
        let (input, raw_code) = be_u32(input)?;
        let (input, flags) = be_u8(input)?;
        if Self::reserved_set(flags) {
            error_flags |= ErrorFlags::NON_ZERO_RESERVED;
        }
        let (input, length) = length(Self::PRE_LENGTH_SIZE)(input)?;
        let header_size = if Self::vendor_specific_flag(flags) {
            Self::PRE_LENGTH_SIZE + 4
        } else {
            Self::PRE_LENGTH_SIZE
        };
        if (length as usize) < header_size {
            return Err(nom::Err::Error((input, ErrorKind::LengthValue)));
        }
        let data_length = (length as usize) - header_size;
        let (input, vendor_id) = if Self::vendor_specific_flag(flags) {
            let (input, v) = be_u32(input)?;
            (input, Some(v))
        } else {
            (input, None)
        };

        let (input, data) = take(data_length)(input)?;
        let (input, padding) = take(Self::padding(data_length))(input)?;
        if !padding.iter().all(|&item| item == 0) {
            error_flags |= ErrorFlags::NON_ZERO_PADDING;
        }
        let attribute = Attribute::new(raw_code);
        let value = match Value::new(&attribute.code, data) {
            Ok((rest, (value, flags))) => {
                if !rest.is_empty() {
                    error_flags |= ErrorFlags::DATA_LENGTH;
                }
                error_flags |= flags;
                value
            }
            Err(nom::Err::Error((_, ErrorKind::LengthValue))) | Err(nom::Err::Incomplete(_)) => {
                error_flags |= ErrorFlags::DATA_LENGTH;
                Value::Unhandled(data.into())
            }
            Err(_) => {
                error_flags |= ErrorFlags::DATA_VALUE;
                Value::Unhandled(data.into())
            }
        };

        Ok((
            input,
            (
                Self {
                    attribute,
                    flags,
                    length,
                    vendor_id,
                    value,
                    padding: padding.into(),
                },
                error_flags,
            ),
        ))
    }
}

impl std::fmt::Display for ErrorFlags {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

impl Protocol<'_> for Diameter {
    type Message = Message;

    fn name() -> &'static str {
        "diameter"
    }
}

fn parse_avps(input: &[u8]) -> IResult<&[u8], (Vec<AVP>, ErrorFlags)> {
    let (rest, avps_flags) = many0(combinator::complete(AVP::parse))(input)?;
    if !rest.is_empty() {
        // many0 will stop if subparser fails, but should read all
        Err(nom::Err::Error((input, ErrorKind::Many0)))
    } else {
        let mut error_flags = ErrorFlags::NONE;
        let mut avps = Vec::new();
        for (avp, flag) in avps_flags {
            error_flags |= flag;
            avps.push(avp)
        }

        Ok((rest, (avps, error_flags)))
    }
}

impl<'a> Parse<'a> for Diameter {
    fn parse(
        &self,
        input: &'a [u8],
        _direction: Direction,
    ) -> Result<(&'a [u8], Option<Self::Message>)> {
        let mut error_flags = ErrorFlags::NONE;
        let (input, (header, flags)) = Header::parse(input)?;
        error_flags |= flags;

        // Don't have to worry about splitting slice causing incomplete
        // Because we have verified the length in Header::parse
        let (input, avps_input) = combinator::complete(take(header.length()))(input)?;
        let (_, (avps, flags)) = parse_avps(avps_input)?;
        error_flags |= flags;
        Ok((
            input,
            Some(Message {
                header,
                avps,
                error_flags,
            }),
        ))
    }
}

impl<'a> Probe<'a> for Diameter {}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use sawp::error;
    use sawp::probe::Status;

    #[test]
    fn test_name() {
        assert_eq!(Diameter::name(), "diameter");
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Err(nom::Err::Incomplete(nom::Needed::Size(1)))),
        case::hello_world(b"hello world", Err(nom::Err::Error((b"hello world" as &[u8], ErrorKind::Tag)))),
        case::invalid_length(
            &[
                // Version: 1
                0x01,
                // Length: 12
                0x00, 0x00, 0x0c,
                // Flags: 128 (Request)
                0x80,
                // Code: 257 (Capability-Exchange)
                0x00, 0x01, 0x01,
                // Application ID: 0 (Diameter Common Messages)
                0x00, 0x00, 0x00, 0x00,
                // Hop-by-Hop ID: 0x53cafe6a
                0x53, 0xca, 0xfe, 0x6a,
                // End-to-End ID: 0x7dc0a11b
                0x7d, 0xc0, 0xa1, 0x1b,
            ],
            Err(nom::Err::Error((
                &[
                    // Flags: 128 (Request)
                    0x80_u8,
                    // Code: 257 (Capability-Exchange)
                    0x00, 0x01, 0x01,
                    // Application ID: 0 (Diameter Common Messages)
                    0x00, 0x00, 0x00, 0x00,
                    // Hop-by-Hop ID: 0x53cafe6a
                    0x53, 0xca, 0xfe, 0x6a,
                    // End-to-End ID: 0x7dc0a11b
                    0x7d, 0xc0, 0xa1, 0x1b,
                ] as &[u8],
                ErrorKind::LengthValue))
            )
        ),
        case::diagnostic(
            &[
                // Version: 1
                0x01,
                // Length: 20
                0x00, 0x00, 0x14,
                // Flags: 128 (Request)
                0x80,
                // Code: 257 (Capability-Exchange)
                0x00, 0x01, 0x01,
                // Application ID: 0 (Diameter Common Messages)
                0x00, 0x00, 0x00, 0x00,
                // Hop-by-Hop ID: 0x53cafe6a
                0x53, 0xca, 0xfe, 0x6a,
                // End-to-End ID: 0x7dc0a11b
                0x7d, 0xc0, 0xa1, 0x1b,
            ],
            Ok((&[] as &[u8],
            (
                Header {
                    version: 1,
                    length: 20,
                    flags: 128,
                    code: 257,
                    app_id: 0,
                    hop_id: 0x53ca_fe6a,
                    end_id: 0x7dc0_a11b,
                },
                ErrorFlags::NONE,
            )))
        ),
        case::reserved_set(
            &[
                // Version: 1
                0x01,
                // Length: 20
                0x00, 0x00, 0x14,
                // Flags: 128 (Request)
                0x0f,
                // Code: 257 (Capability-Exchange)
                0x00, 0x01, 0x01,
                // Application ID: 0 (Diameter Common Messages)
                0x00, 0x00, 0x00, 0x00,
                // Hop-by-Hop ID: 0x53cafe6a
                0x53, 0xca, 0xfe, 0x6a,
                // End-to-End ID: 0x7dc0a11b
                0x7d, 0xc0, 0xa1, 0x1b,
            ],
            Ok((&[] as &[u8],
            (
                Header {
                    version: 1,
                    length: 20,
                    flags: 15,
                    code: 257,
                    app_id: 0,
                    hop_id: 0x53ca_fe6a,
                    end_id: 0x7dc0_a11b,
                },
                ErrorFlags::NON_ZERO_RESERVED,
            )))
        ),
        case::diagnostic(
            &[
                // Version: 1
                0x01,
                // Length: 24
                0x00, 0x00, 0x18,
                // Flags: 128 (Request)
                0x80,
                // Code: 257 (Capability-Exchange)
                0x00, 0x01, 0x01,
                // Application ID: 0 (Diameter Common Messages)
                0x00, 0x00, 0x00, 0x00,
                // Hop-by-Hop ID: 0x53cafe6a
                0x53, 0xca, 0xfe, 0x6a,
                // End-to-End ID: 0x7dc0a11b
                0x7d, 0xc0, 0xa1, 0x1b,
            ],
            Err(nom::Err::Incomplete(nom::Needed::Size(4)))
        ),
    )]
    fn test_header(input: &[u8], expected: IResult<&[u8], (Header, ErrorFlags)>) {
        assert_eq!(Header::parse(input), expected);
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Err(nom::Err::Incomplete(nom::Needed::Size(4)))),
        case::diagnostic(
            &[
                // Code: 264 (Origin-Host)
                0x00, 0x00, 0x01, 0x08,
                // Flags: 40 (Mandatory)
                0x40,
                // Length: 31
                0x00, 0x00, 0x1f,
                // Data: "backend.eap.testbed.aaa"
                0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x2e,
                0x65, 0x61, 0x70, 0x2e, 0x74, 0x65, 0x73, 0x74,
                0x62, 0x65, 0x64, 0x2e, 0x61, 0x61, 0x61,
                // Padding: 1
                0x00,
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 264,
                        code: AttributeCode::OriginHost,
                    },
                    flags: 0x40,
                    length: 31,
                    vendor_id: None,
                    value: Value::DiameterIdentity("backend.eap.testbed.aaa".into()),
                    padding: vec![0x00],
                },
                ErrorFlags::NONE,
            )))
        ),
        case::diagnostic_vendor_id(
            &[
                // Code: 264 (Origin-Host)
                0x00, 0x00, 0x01, 0x08,
                // Flags: 0x80 (Vendor-Id)
                0x80,
                // Length: 12
                0x00, 0x00, 0x0c,
                // Vendor-Id: 1234567890
                0x49, 0x96, 0x02, 0xd2,
                // Data:
                // Padding:
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 264,
                        code: AttributeCode::OriginHost,
                    },
                    flags: 0x80,
                    length: 12,
                    vendor_id: Some(1_234_567_890u32),
                    value: Value::DiameterIdentity("".into()),
                    padding: Vec::new(),
                },
                ErrorFlags::NONE,
            )))
        ),
        case::unsigned_32_format(
            &[
               // Code: 266 (Vendor-Id)
               0x00, 0x00, 0x01, 0x0a,
               // Flags: 0x00
               0x00,
               // Length: 13,
               0x00, 0x00, 0x0d,
               // Vendor-Id:
               // Data:
               0x00, 0x00, 0x00, 0x7b,
               0x01,
               // Padding
               0x00, 0x00, 0x00,
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 266,
                        code: AttributeCode::VendorId,
                    },
                    flags: 0x00,
                    length: 13,
                    vendor_id: None,
                    value: Value::Unsigned32(123),

                    padding: vec![0x00, 0x00, 0x00],
                },
                ErrorFlags::DATA_LENGTH,
            )))
        ),
        case::unsigned_64_format(
            &[
               // Code: 287 (Accouting-Realtime-Required)
               0x00, 0x00, 0x01, 0x1f,
               // Flags: 0x00
               0x00,
               // Length: 16,
               0x00, 0x00, 0x10,
               // Vendor-Id:
               // Data:
               0x00, 0x00, 0x00, 0x7B,
               0x01, 0x02, 0x02, 0x03,
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 287,
                        code: AttributeCode::AccountingSubSessionId,
                    },
                    flags: 0x00,
                    length: 16,
                    vendor_id: None,
                    value: Value::Unsigned64(528297886211),
                    padding: Vec::new(),
                },
                ErrorFlags::NONE,
            )))
        ),
        case::enumerated_format(
            &[
               // Code: 483 (Accounting-Realtime-Required)
               0x00, 0x00, 0x01, 0xe3,
               // Flags: 0x00
               0x00,
               // Length: 12,
               0x00, 0x00, 0x0c,
               // Vendor-Id:
               // Data: Grant-And-Store (2)
               0x00, 0x00, 0x00, 0x02,
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 483,
                        code: AttributeCode::AccountingRealtimeRequired,
                    },
                    flags: 0x00,
                    length: 12,
                    vendor_id: None,
                    value: Value::Enumerated(2),
                    padding: Vec::new(),
                },
                ErrorFlags::NONE,
            )))
        ),
        case::octet_string_format(
            &[
               // Code: 44 (AcctSessionId)
               0x00, 0x00, 0x00, 0x2c,
               // Flags: 0x00
               0x00,
               // Length: 15,
               0x00, 0x00, 0x0f,
               // Vendor-Id:
               // Data:
               0x01, 0x02, 0x03, 0x04,
               0x05, 0x06, 0x07,
               // Padding:
               0xef,
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 44,
                        code: AttributeCode::AcctSessionId,
                    },
                    flags: 0x00,
                    length: 15,
                    vendor_id: None,
                    value: Value::OctetString(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                    padding: vec![0xef],
                },
                ErrorFlags::NON_ZERO_PADDING,
            )))
        ),
        case::utf8_string_format(
            &[
               // Code: 1 (Username)
               0x00, 0x00, 0x00, 0x01,
               // Flags: 0x00
               0x00,
               // Length: 20,
               0x00, 0x00, 0x14,
               // Vendor-Id:
               // Data: Hello World!
               0x48, 0x65, 0x6c, 0x6c,
               0x6f, 0x20, 0x57, 0x6f,
               0x72, 0x6c, 0x64, 0x21,
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 1,
                        code: AttributeCode::UserName,
                    },
                    flags: 0x00,
                    length: 20,
                    vendor_id: None,
                    value: Value::UTF8String("Hello World!".into()),
                    padding: Vec::new(),
                },
                ErrorFlags::NONE,
            )))
        ),
        case::diameter_uri_format(
            &[
               // Code: 292 (RedirectHost)
               0x00, 0x00, 0x01, 0x24,
               // Flags: 0x00
               0x00,
                   // Length: 19,
               0x00, 0x00, 0x13,
               // Vendor-Id:
            // Data: example.com
            0x65, 0x78, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2e,
            0x63, 0x6f, 0x6d,
            // Padding:
            0x00,
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 292,
                        code: AttributeCode::RedirectHost,
                    },
                    flags: 0x00,
                    length: 19,
                    vendor_id: None,
                    value: Value::DiameterURI("example.com".into()),
                    padding: vec![0x00],
                },
                ErrorFlags::NONE,
            )))
        ),
        case::address_v4_format(
            &[
               // Code: 257 (HostIPAddress)
               0x00, 0x00, 0x01, 0x01,
               // Flags: 0x0f
               0x0f,
               // Length: 12,
               0x00, 0x00, 0x0c,
               // Vendor-Id:
               // Data: 10.10.0.1
               0x0a, 0x0a, 0x00, 0x01,
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 257,
                        code: AttributeCode::HostIPAddress,
                    },
                    flags: 0x0f,
                    length: 12,
                    vendor_id: None,
                    value: Value::Address(IpAddr::V4(Ipv4Addr::new(10, 10, 0, 1))),
                    padding: Vec::new(),
                },
                ErrorFlags::NON_ZERO_RESERVED,
            )))
        ),
        case::address_v6_format(
            &[
               // Code: 257 (HostIPAddress)
               0x00, 0x00, 0x01, 0x01,
               // Flags: 0x00
               0x00,
               // Length: 24,
               0x00, 0x00, 0x18,
               // Vendor-Id:
               // Data: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
               0x20, 0x01, 0x0d, 0xb8,
               0x85, 0xa3, 0x00, 0x00,
               0x00, 0x00, 0x8a, 0x2e,
               0x03, 0x70, 0x73, 0x34,
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 257,
                        code: AttributeCode::HostIPAddress,
                    },
                    flags: 0x00,
                    length: 24,
                    vendor_id: None,
                    value: Value::Address(IpAddr::V6(Ipv6Addr::new(
                                0x2001, 0x0db8, 0x85a3, 0x0000,
                                0x0000, 0x8a2e, 0x0370, 0x7334))),
                    padding: Vec::new(),
                },
                ErrorFlags::NONE,
            )))
        ),
        case::time_format(
            &[
               // Code: 55 (EventTimestamp)
               0x00, 0x00, 0x00, 0x37,
               // Flags: 0x00
               0x00,
               // Length: 12,
               0x00, 0x00, 0x0c,
               // Vendor-Id:
               // Data: 3794601600 (March 31, 2021)
               0xe2, 0x2d, 0x06, 0x80
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 55,
                        code: AttributeCode::EventTimestamp,
                    },
                    flags: 0x00,
                    length: 12,
                    vendor_id: None,
                    value: Value::Time(3794601600),
                    padding: Vec::new(),
                },
                ErrorFlags::NONE,
            )))
        ),
        case::grouped_format(
            &[
            // Code: 297 (ExperimentalResult)
            0x00, 0x00, 0x01, 0x29,
            // Flags: 0x00
            0x00,
            // Length: 44,
            0x00, 0x00, 0x2c,
            // Vendor-Id:
            // Data:

            // AVPs[0]
            // Code: 264 (OriginHost)
            0x00, 0x00, 0x01, 0x08,
            // Flags: 0x00
            0x00,
            // Length: 19,
            0x00, 0x00, 0x13,
            // Vendor-Id:
            // Data: example.com
            0x65, 0x78, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2e,
            0x63, 0x6f, 0x6d,
            // Padding:
            0x01,

            // AVPs[1]
            // Code: 44 ( AcctSessionId)
            0x00, 0x00, 0x00, 0x2c,
            // Flags: 0x0f,
            0x0f,
            // Length: 15,
            0x00, 0x00, 0x0f,
            // Vendor-Id:
            // Data:
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07,
            // Padding:
            0x00,
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 297,
                        code: AttributeCode::ExperimentalResult,
                    },
                    flags: 0x00,
                    length: 44,
                    vendor_id: None,
                    value: Value::Grouped(vec![
                        AVP {
                            attribute: Attribute {
                                raw: 264,
                                code: AttributeCode::OriginHost,
                            },
                            flags: 0x00,
                            length: 19,
                            vendor_id: None,
                            value: Value::DiameterIdentity("example.com".into()),
                            padding: vec![0x01],
                        },
                        AVP {
                            attribute: Attribute {
                                raw: 44,
                                code: AttributeCode::AcctSessionId,
                            },
                            flags: 0x0f,
                            length: 15,
                            vendor_id: None,
                            value: Value::OctetString(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
                            padding: vec![0x00],
                        }]),
                    padding: Vec::new(),
                },
                ErrorFlags::NON_ZERO_PADDING | ErrorFlags::NON_ZERO_RESERVED
            )))
        ),
        case::invalid_utf8(
            &[
               // Code: 1 (Username)
               0x00, 0x00, 0x00, 0x01,
               // Flags: 0x00
               0x00,
               // Length: 12,
               0x00, 0x00, 0x0c,
               // Vendor-Id:
               // Data:
               0xfe, 0xfe, 0xff, 0xff,
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 1,
                        code: AttributeCode::UserName,
                    },
                    flags: 0x00,
                    length: 12,
                    vendor_id: None,
                    value: Value::Unhandled(vec![0xfe, 0xfe, 0xff, 0xff]),
                    padding: Vec::new(),
                },
                ErrorFlags::DATA_VALUE,
            )))
        ),
        case::invalid_address(
            &[
               // Code: 257 (HostIPAddress)
               0x00, 0x00, 0x01, 0x01,
               // Flags: 0x00
               0x00,
               // Length: 13,
               0x00, 0x00, 0x0d,
               // Vendor-Id:
               // Data: 10.10.0.1.1 (Invalid)
               0x0a, 0x0a, 0x00, 0x01, 0x01,
               // Padding
               0x00, 0x00, 0x00,
            ],
            Ok((&[] as &[u8],
            (
                AVP {
                    attribute: Attribute {
                        raw: 257,
                        code: AttributeCode::HostIPAddress,
                    },
                    flags: 0x00,
                    length: 13,
                    vendor_id: None,
                    value: Value::Unhandled(vec![0x0a, 0x0a, 0x00, 0x01, 0x01]),
                    padding: vec![0x00, 0x00, 0x00],
                },
                ErrorFlags::DATA_LENGTH,
            )))
        ),
        case::unhandled(
            &[
               // Code: 2
               0x00, 0x00, 0x00, 0x02,
               // Flags: 0x00
               0x00,
               // Length: 13,
               0x00, 0x00, 0x0d,
               // Vendor-Id:
               // Data: 10.10.0.1.1 (Invalid)
               0x0a, 0x0a, 0x00, 0x01, 0x01,
               // Padding
               0x00, 0x00, 0x00,
            ],
            Ok((&[] as &[u8],
            (
                    AVP {
                    attribute: Attribute {
                        raw: 2,
                        code: AttributeCode::Unknown,
                    },
                    flags: 0x00,
                    length: 13,
                    vendor_id: None,
                    value: Value::Unhandled(vec![0x0a, 0x0a, 0x00, 0x01, 0x01]),
                    padding: vec![0x00, 0x00, 0x00],
                },
                ErrorFlags::NONE,
            )))
        )
    )]
    fn test_avp(input: &[u8], expected: IResult<&[u8], (AVP, ErrorFlags)>) {
        assert_eq!(AVP::parse(input), expected);
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Err(error::Error::incomplete_needed(1))),
        case::header(
        &[
            // Version: 1
            0x01,
            // Length: 20
            0x00, 0x00, 0x14,
            // Flags: 128 (Request)
            0x80,
            // Code: 257 (Capability-Exchange)
            0x00, 0x01, 0x01,
            // Application ID: 0 (Diameter Common Messages)
            0x00, 0x00, 0x00, 0x00,
            // Hop-by-Hop ID: 0x53cafe6a
            0x53, 0xca, 0xfe, 0x6a,
            // End-to-End ID: 0x7dc0a11b
            0x7d, 0xc0, 0xa1, 0x1b,
            ],
            Ok((&[] as &[u8],
                Some(Message {
                    header: Header {
                        version: 1,
                        length: 20,
                        flags: 128,
                        code: 257,
                        app_id: 0,
                        hop_id: 0x53ca_fe6a,
                        end_id: 0x7dc0_a11b,
                    },
                    avps: Vec::new(),
                    error_flags: ErrorFlags::NONE,
                })
            ))
        ),
        case::full_message(
        &[
            // Header
            // Version: 1
            0x01,
            // Length: 64
            0x00, 0x00, 0x40,
            // Flags: 128 (Request)
            0x8f,
            // Code: 257 (Capability-Exchange)
            0x00, 0x01, 0x01,
            // Application ID: 0 (Diameter Common Messages)
            0x00, 0x00, 0x00, 0x00,
            // Hop-by-Hop ID: 0x53cafe6a
            0x53, 0xca, 0xfe, 0x6a,
            // End-to-End ID: 0x7dc0a11b
            0x7d, 0xc0, 0xa1, 0x1b,

            //AVPs[0]
            // Code: 264 (Origin-Host)
            0x00, 0x00, 0x01, 0x08,
            // Flags: 40 (Mandatory)
            0x40,
            // Length: 31
            0x00, 0x00, 0x1f,
            // Data: "backend.eap.testbed.aaa"
            0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x2e,
            0x65, 0x61, 0x70, 0x2e, 0x74, 0x65, 0x73, 0x74,
            0x62, 0x65, 0x64, 0x2e, 0x61, 0x61, 0x61,
            // Padding: 1
            0x01,

            // AVPS[1]
            // Code: 264 (Origin-Host)
            0x00, 0x00, 0x01, 0x08,
            // Flags: 0x80 (Vendor-Id)
            0x80,
            // Length: 12
            0x00, 0x00, 0x0c,
            // Vendor-Id: 1234567890
            0x49, 0x96, 0x02, 0xd2,
            // Data:
            // Padding:
        ],
        Ok((&[] as &[u8],
            Some(Message {
                header: Header {
                    version: 1,
                    length: 64,
                    flags: 143,
                    code: 257,
                    app_id: 0,
                    hop_id: 0x53ca_fe6a,
                    end_id: 0x7dc0_a11b,
                },
                avps: vec![
                    AVP {
                        attribute: Attribute {
                            raw: 264,
                            code: AttributeCode::OriginHost,
                        },
                        flags: 0x40,
                        length: 31,
                        vendor_id: None,
                        value: Value::DiameterIdentity("backend.eap.testbed.aaa".into()),
                        padding: vec![0x01],
                    },
                    AVP {
                        attribute: Attribute {
                            raw: 264,
                            code: AttributeCode::OriginHost,
                        },
                        flags: 0x80,
                        length: 12,
                        vendor_id: Some(1_234_567_890u32),
                        value: Value::DiameterIdentity("".into()),
                        padding: Vec::new(),
                    },
                ],
                error_flags : ErrorFlags::NON_ZERO_RESERVED | ErrorFlags::NON_ZERO_PADDING,
            })
        ))),
        case::incomplete(
            &[
                // Header
                // Version: 1
                0x01,
                // Length: 66
                0x00, 0x00, 0x42,
                // Flags: 128 (Request)
                0x80,
                // Code: 257 (Capability-Exchange)
                0x00, 0x01, 0x01,
                // Application ID: 0 (Diameter Common Messages)
                0x00, 0x00, 0x00, 0x00,
                // Hop-by-Hop ID: 0x53cafe6a
                0x53, 0xca, 0xfe, 0x6a,
                // End-to-End ID: 0x7dc0a11b
                0x7d, 0xc0, 0xa1, 0x1b,

                //AVPs[0]
                // Code: 264 (Origin-Host)
                0x00, 0x00, 0x01, 0x08,
                // Flags: 40 (Mandatory)
                0x40,
                // Length: 31
                0x00, 0x00, 0x1f,
                // Data: "backend.eap.testbed.aaa"
                0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x2e,
                0x65, 0x61, 0x70, 0x2e, 0x74, 0x65, 0x73, 0x74,
                0x62, 0x65, 0x64, 0x2e, 0x61, 0x61, 0x61,
                // Padding: 1
                0x00,

                // AVPS[1]
                // Code: 264 (Origin-Host)
                0x00, 0x00, 0x01, 0x08,
                // Flags: 0x80 (Vendor-Id)
                0x80,
                // Length: 14
                0x00, 0x00, 0x0e,
                // Vendor-Id: 1234567890
                0x49, 0x96, 0x02, 0xd2,
                // Data:
                // Padding:
            ],
            Err(error::Error::incomplete_needed(2))
        ),
        case::invalid_avp(
            &[
                // Header
                // Version: 1
                0x01,
                // Length: 64
                0x00, 0x00, 0x40,
                // Flags: 128 (Request)
                0x80,
                // Code: 257 (Capability-Exchange)
                0x00, 0x01, 0x01,
                // Application ID: 0 (Diameter Common Messages)
                0x00, 0x00, 0x00, 0x00,
                // Hop-by-Hop ID: 0x53cafe6a
                0x53, 0xca, 0xfe, 0x6a,
                // End-to-End ID: 0x7dc0a11b
                0x7d, 0xc0, 0xa1, 0x1b,

                //AVPs[0]
                // Code: 264 (Origin-Host)
                0x00, 0x00, 0x01, 0x08,
                // Flags: 40 (Mandatory)
                0x40,
                // Length: 31
                0x00, 0x00, 0x1f,
                // Data: "backend.eap.testbed.aaa"
                0x62, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x2e,
                0x65, 0x61, 0x70, 0x2e, 0x74, 0x65, 0x73, 0x74,
                0x62, 0x65, 0x64, 0x2e, 0x61, 0x61, 0x61,
                // Padding: 1
                0x00,

                // AVPS[1]
                // Code: 264 (Origin-Host)
                0x00, 0x00, 0x01, 0x08,
                // Flags: 0x80 (Vendor-Id)
                0x80,
                // Length: 14
                0x00, 0x00, 0x0e,
                // Vendor-Id: 1234567890
                0x49, 0x96, 0x02, 0xd2,
                // Data:
                // Padding:
            ],
            Err(error::Error::parse(Some("Many0".to_string()))),
        ),
    )]
    fn test_parse(input: &[u8], expected: Result<(&[u8], Option<Message>)>) {
        let diameter = Diameter {};

        assert_eq!(diameter.parse(input, Direction::Unknown), expected);
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Status::Incomplete),
        case::hello_world(b"hello world", Status::Unrecognized),
        case::header(
        &[
            // Version: 1
            0x01,
            // Length: 20
            0x00, 0x00, 0x14,
            // Flags: 128 (Request)
            0x80,
            // Code: 257 (Capability-Exchange)
            0x00, 0x01, 0x01,
            // Application ID: 0 (Diameter Common Messages)
            0x00, 0x00, 0x00, 0x00,
            // Hop-by-Hop ID: 0x53cafe6a
            0x53, 0xca, 0xfe, 0x6a,
            // End-to-End ID: 0x7dc0a11b
            0x7d, 0xc0, 0xa1, 0x1b,
            ],
            Status::Recognized
        ),
    )]
    fn test_probe(input: &[u8], expected: Status) {
        let diameter = Diameter {};

        assert_eq!(diameter.probe(input, Direction::Unknown), expected);
    }
}
