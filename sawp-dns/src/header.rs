use nom::number::streaming::be_u16;

use sawp::error::Result;

use sawp_flags::{BitFlags, Flag, Flags};

use crate::enums::{OpCode, QueryResponse, ResponseCode};

use crate::ErrorFlags;
#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

/// Masks for extracting DNS header flags
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, BitFlags)]
#[repr(u16)]
pub enum header_masks {
    QUERY_RESPONSE = 0b1000_0000_0000_0000,
    OPCODE = 0b0111_1000_0000_0000,
    AUTH = 0b0000_0100_0000_0000,
    TRUNC = 0b0000_0010_0000_0000,
    RECUR_DESIRED = 0b0000_0001_0000_0000,
    RECUR_AVAIL = 0b0000_0000_1000_0000,
    Z = 0b0000_0000_0100_0000,
    AUTH_DATA = 0b0000_0000_0010_0000,
    CHECK_DISABLED = 0b0000_0000_0001_0000,
    RCODE = 0b0000_0000_0000_1111,
}

/// A parsed DNS header
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_dns"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Header {
    /// Transaction ID
    pub transaction_id: u16,
    /// Raw header flags
    pub flags: u16,
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    /// QueryResponse::Query or QueryResponse::Response
    pub query_response: QueryResponse,
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    /// Type of query
    pub opcode: OpCode,
    /// Is the name server an authority for this domain name?
    pub authoritative: bool,
    /// Was this msg truncated?
    pub truncated: bool,
    /// Should the name server pursue the query recursively?
    pub recursion_desired: bool,
    /// Can the name server pursue the query recursively?
    pub recursion_available: bool,
    /// Z flag is set?
    pub zflag: bool,

    /// All data authenticated by the server
    pub authenticated_data: bool,

    pub check_disabled: bool,
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    /// Name server success/error state
    pub rcode: ResponseCode,
    /// Number of questions provided
    pub qdcount: u16,
    /// Number of answers provided
    pub ancount: u16,
    /// Number of name server resource records in the auth records
    pub nscount: u16,
    /// Number of resource records in the additional records section
    pub arcount: u16,
}

impl Header {
    #[allow(clippy::type_complexity)]
    pub fn parse(input: &[u8]) -> Result<(&[u8], (Header, Flags<ErrorFlags>))> {
        let mut error_flags = ErrorFlags::none();

        let (input, txid) = be_u16(input)?;
        let (input, flags) = be_u16(input)?;
        let wrapped_flags = Flags::<header_masks>::from_bits(flags);
        let query = if wrapped_flags.intersects(header_masks::QUERY_RESPONSE) {
            QueryResponse::Response
        } else {
            QueryResponse::Query
        };
        let opcode: OpCode = OpCode::from_raw((wrapped_flags & header_masks::OPCODE).bits() >> 10);
        if opcode == OpCode::UNKNOWN {
            error_flags |= ErrorFlags::UnknownOpcode;
        }
        let rcode: ResponseCode =
            ResponseCode::from_raw((wrapped_flags & header_masks::RCODE).bits());
        if rcode == ResponseCode::UNKNOWN {
            error_flags |= ErrorFlags::UnknownRcode;
        }
        let (input, qcnt) = be_u16(input)?;
        let (input, acnt) = be_u16(input)?;
        let (input, nscnt) = be_u16(input)?;
        let (input, arcnt) = be_u16(input)?;

        Ok((
            input,
            (
                Header {
                    transaction_id: txid,
                    flags,
                    query_response: query,
                    opcode,
                    authoritative: wrapped_flags.intersects(header_masks::AUTH),
                    truncated: wrapped_flags.intersects(header_masks::TRUNC),
                    recursion_desired: wrapped_flags.intersects(header_masks::RECUR_DESIRED),
                    recursion_available: wrapped_flags.intersects(header_masks::RECUR_AVAIL),
                    zflag: wrapped_flags.intersects(header_masks::Z),
                    authenticated_data: wrapped_flags.intersects(header_masks::AUTH_DATA),
                    check_disabled: wrapped_flags.intersects(header_masks::CHECK_DISABLED),
                    rcode,
                    qdcount: qcnt,
                    ancount: acnt,
                    nscount: nscnt,
                    arcount: arcnt,
                },
                error_flags,
            ),
        ))
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::type_complexity)]

    use crate::{ErrorFlags, Header, OpCode, QueryResponse, ResponseCode};
    use rstest::rstest;
    use sawp::error::{Error, Result};
    use sawp_flags::{Flag, Flags};

    #[rstest(
        input,
        expected,
        case::parse_simple_header(
            & [
                0x31, 0x21, // Transaction ID: 0x3121
                0x81, 0x00, // Flags: response, recursion desired
                0x00, 0x01, // QDCOUNT: 1
                0x00, 0x01, // ANCOUNT: 1
                0x00, 0x00, // NSCOUNT: 0
                0x00, 0x00, // ARCOUNT: 0
            ],
            Ok((
                b"".as_ref(),
                (Header {
                    transaction_id: 0x3121,
                    flags: 0b1000_0001_0000_0000,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::QUERY,
                    authoritative: false,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: false,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NOERROR,
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0,
                },
                ErrorFlags::none())
            ))
        ),
        case::parse_too_short_header(
            & [
                0x31, 0x21, // Transaction ID: 0x3121
                0x81, 0x00, // Flags: response, recursion desired
                0x00, 0x01, // QDCOUNT: 1
                0x00, 0x01, // ANCOUNT: 1
                0x00, 0x00, // NSCOUNT: 0
            ],
            Err(Error::incomplete_needed(2))
        ),
        case::parse_header_bad_opcode(
            & [
                0x31, 0x21, // Transaction ID: 0x3121
                0xb1, 0x00, // Flags: invalid opcode, recursion desired, authenticated data, format error
                0x00, 0x01, // QDCOUNT: 1
                0x00, 0x01, // ANCOUNT: 1
                0x00, 0x00, // NSCOUNT: 0
                0x00, 0x00, // ARCOUNT: 0
            ],
            Ok((
                b"".as_ref(),
                (Header {
                    transaction_id: 0x3121,
                    flags: 0b1011_0001_0000_0000,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::UNKNOWN,
                    authoritative: false,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: false,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NOERROR,
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0,
                },
                ErrorFlags::UnknownOpcode.into())
            ))
        ),
        case::parse_header_bad_rcode(
            & [
                0x31, 0x21, // Transaction ID: 0x3121
                0x81, 0x0c, // Flags: response, recursion desired, invalid rcode
                0x00, 0x01, // QDCOUNT: 1
                0x00, 0x01, // ANCOUNT: 1
                0x00, 0x00, // NSCOUNT: 0
                0x00, 0x00, // ARCOUNT: 0
            ],
            Ok((
            b"".as_ref(),
            (Header {
                transaction_id: 0x3121,
                flags: 0b1000_0001_0000_1100,
                query_response: QueryResponse::Response,
                opcode: OpCode::QUERY,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: false,
                zflag: false,
                authenticated_data: false,
                check_disabled: false,
                rcode: ResponseCode::UNKNOWN,
                qdcount: 1,
                ancount: 1,
                nscount: 0,
                arcount: 0,
            },
            ErrorFlags::UnknownRcode.into())
            ))
        ),
    )]
    fn header(input: &[u8], expected: Result<(&[u8], (Header, Flags<ErrorFlags>))>) {
        assert_eq!(Header::parse(input), expected);
    }
}
