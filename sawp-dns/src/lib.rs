//! A DNS protocol parser. Given bytes and a [`sawp::parser::Direction`], it will
//! attempt to parse the bytes and return a [`Message`]. The parser will
//! inform the caller about what went wrong if no message is returned (see [`sawp::parser::Parse`]
//! for details on possible return types).
//!
//! The following protocol references were used to create this module:
//!
//! [RFC1035](https://tools.ietf.org/html/rfc1035)
//! [RFC1123](https://tools.ietf.org/html/rfc1123)
//! [RFC2065](https://tools.ietf.org/html/rfc2065)
//! [RFC2505](https://tools.ietf.org/html/rfc2505)
//! [RFC2535](https://tools.ietf.org/html/rfc2535)
//! [RFC2845](https://tools.ietf.org/html/rfc2845)
//! [RFC2930](https://tools.ietf.org/html/rfc2930)
//! [RFC3655](https://tools.ietf.org/html/rfc3655)
//! [RFC4255](https://tools.ietf.org/html/rfc4255)
//! [RFC4408](https://tools.ietf.org/html/rfc4408)
//! [RFC4635](https://tools.ietf.org/html/rfc4635)
//! [RFC5001](https://tools.ietf.org/html/rfc5001)
//! [RFC6742](https://tools.ietf.org/html/rfc6742)
//! [RFC6891](https://tools.ietf.org/html/rfc6891)
//! [RFC6975](https://tools.ietf.org/html/rfc6975)
//! [RFC7314](https://tools.ietf.org/html/rfc7314)
//! [RFC7828](https://tools.ietf.org/html/rfc7828)
//! [RFC7830](https://tools.ietf.org/html/rfc7830)
//! [RFC7871](https://tools.ietf.org/html/rfc7871)
//! [RFC7873](https://tools.ietf.org/html/rfc7873)
//! [RFC7901](https://tools.ietf.org/html/rfc7901)
//! [RFC8145](https://tools.ietf.org/html/rfc8145)
//! [RFC8764](https://tools.ietf.org/html/rfc8764)
//! [RFC8914](https://tools.ietf.org/html/rfc8914)
//! [Cisco - Identifying DNS Traffic](https://docs.umbrella.com/umbrella-api/docs/identifying-dns-traffic2)
//! [Draft DNSOP Zone Digest](https://tools.ietf.org/html/draft-ietf-dnsop-dns-zone-digest-14)
//! [Draft DNSOP SVCB](https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/00)
//! [Draft EDNS Tags](https://datatracker.ietf.org/doc/draft-bellis-dnsop-edns-tags/)
//! [Eastlake Kitchen Sink](https://tools.ietf.org/html/draft-eastlake-kitchen-sink)
//! [NIMROD DNS](https://tools.ietf.org/html/draft-ietf-nimrod-dns-00)
//! [Wijngaard's](https://tools.ietf.org/html/draft-wijngaards-dnsop-trust-history-02)
//! [DNS Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
//!
//! # Example
//! ```
//! use sawp::parser::{Direction, Parse};
//! use sawp::error::Error;
//! use sawp::error::ErrorKind;
//! use sawp_dns::{Dns, Message};
//!
//! fn parse_bytes(input: &[u8]) -> std::result::Result<&[u8], Error> {
//!     let dns = Dns {};
//!     let mut bytes = input;
//!     while bytes.len() > 0 {
//!         // If we know that this is a request or response, change the Direction
//!         // for a more accurate parsing
//!         match dns.parse(bytes, Direction::Unknown) {
//!             // The parser succeeded and returned the remaining bytes and the parsed DNS message
//!             Ok((rest, Some(message))) => {
//!                 println!("Dns message: {:?}", message);
//!                 bytes = rest;
//!             }
//!             // The parser recognized that this might be DNS and made some progress,
//!             // but more bytes are needed
//!             Ok((rest, None)) => return Ok(rest),
//!             // The parser was unable to determine whether this was DNS or not and more
//!             // bytes are needed
//!             Err(Error { kind: ErrorKind::Incomplete(_) }) => return Ok(bytes),
//!             // The parser determined that this was not DNS
//!             Err(e) => return Err(e)
//!         }
//!     }
//!
//!     Ok(bytes)
//! }
//! ```

use sawp::error::{NomError, Result};
use sawp::parser::{Direction, Parse};
use sawp::probe::Probe;
use sawp::protocol::Protocol;
use sawp_flags::{BitFlags, Flag, Flags};

/// FFI structs and Accessors
#[cfg(feature = "ffi")]
mod ffi;

#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

pub mod answer;
use answer::*;

pub mod edns;

pub mod enums;
use enums::*;

pub mod header;
use header::*;

pub mod name;
use name::*;

pub mod question;
use question::*;

pub mod rdata;

use nom::error::ErrorKind;

// This is a helper type for the module since the input will always be
// &'a [u8] and the error will always be (&'a [i8], nom::error::Errorkind)
type IResult<'a, O> = nom::IResult<&'a [u8], O, sawp::error::NomError<&'a [u8]>>;

/// Future: replace with nom's many0 when we migrate to a version with FnMut combinators.
fn custom_many0<O, F>(mut func: F) -> impl FnMut(&[u8]) -> IResult<Vec<O>>
where
    F: FnMut(&[u8]) -> IResult<O>,
{
    move |mut input| {
        // We don't expect more than one EDNS option usually. Since this fn is exclusively used there for now let's keep this small.
        let mut acc = Vec::with_capacity(1);
        loop {
            match func(input) {
                Err(nom::Err::Error(NomError {
                    input: _,
                    code: ErrorKind::LengthValue,
                })) => return Ok((input, acc)),
                Ok((rem, out)) => {
                    if rem == input {
                        return Err(nom::Err::Error(NomError::new(input, ErrorKind::Many0)));
                    }

                    input = rem;
                    acc.push(out);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
}

/// Future: replace with nom's count when we migrate to a version with FnMut combinators.
pub fn custom_count<O, F>(
    mut func: F,
    count: usize,
) -> impl for<'a> FnMut(&'a [u8], &'a [u8]) -> IResult<'a, Vec<O>>
where
    F: for<'a> FnMut(&'a [u8], &'a [u8]) -> IResult<'a, O>,
{
    move |i, reference| {
        let mut input = i;
        let mut res = Vec::with_capacity(count);

        for _ in 0..count {
            let input_ = input;
            match func(input_, reference) {
                Ok((rem, out)) => {
                    res.push(out);
                    input = rem;
                }
                Err(nom::Err::Error(NomError {
                    input,
                    code: ErrorKind::Count,
                })) => {
                    return Ok((input, res));
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok((input, res))
    }
}

/// Error flags raised while parsing DNS - to be used in the returned Message
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, BitFlags)]
pub enum ErrorFlags {
    /// more than one pseudo-RR exists - EDNS specs limit OPT RRs to <=1
    ExtraOptRr = 0b0000_0000_0000_0001,
    /// invalid opcode
    UnknownOpcode = 0b0000_0000_0000_0010,
    /// invalid response code
    UnknownRcode = 0b0000_0000_0000_0100,
    /// invalid record class
    UnknownRclass = 0b0000_0000_0000_1000,
    /// invalid record type
    UnknownRtype = 0b0000_0000_0001_0000,
    /// an option code used in a pseudo-RR is invalid
    EdnsParseFail = 0b0000_0000_0010_0000,
    /// some label exceeds the maximum length of 63
    DnsLabelExceedsMaxLen = 0b0000_0000_0100_0000,
    /// name len > 255 - name will be truncated to max_domain_len
    DnsNameExceedsMaxLen = 0b0000_0000_1000_0000,
    /// a ptr either points to an invalid location or is self-referential
    DnsNameInvalidCompression = 0b0000_0001_0000_0000,
}

/// Breakdown of the parsed dns bytes
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_dns"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub queries: Vec<Question>,
    pub answers: Vec<Answer>,
    pub nameservers: Vec<Answer>,
    pub additional: Vec<Answer>,
    #[cfg_attr(feature = "ffi", sawp_ffi(flag = "u16"))]
    pub error_flags: Flags<ErrorFlags>,
}

impl Message {}

#[derive(Debug)]
pub struct Dns {}

impl<'a> Protocol<'a> for Dns {
    type Message = Message;

    fn name() -> &'static str {
        "dns"
    }
}

impl<'a> Probe<'a> for Dns {}

/// Returns ErrorKind::Incomplete if more data is needed.
/// If part of the message was parsed successfully will attempt to return a partial message
/// with an appropriate error_flags field indicating what went wrong.
impl<'a> Parse<'a> for Dns {
    fn parse(
        &self,
        input: &'a [u8],
        _direction: Direction,
    ) -> Result<(&'a [u8], Option<Self::Message>)> {
        let reference_bytes = input; // An internal copy of the full input used to dereference pointers during parsing.
        let mut message = Message {
            header: Header {
                transaction_id: 0,
                flags: 0,
                query_response: QueryResponse::Response,
                opcode: OpCode::QUERY,
                authoritative: false,
                truncated: false,
                recursion_desired: false,
                recursion_available: false,
                zflag: false,
                authenticated_data: false,
                check_disabled: false,
                rcode: ResponseCode::NOERROR,
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            queries: vec![],
            answers: vec![],
            nameservers: vec![],
            additional: vec![],
            error_flags: ErrorFlags::none(),
        };

        let (input, (header, error_flags)) = Header::parse(input)?;
        message.header = header;
        message.error_flags |= error_flags;

        let (input, (questions, error_flags)) =
            Question::parse_questions(input, reference_bytes, message.header.qdcount.into())?;
        message.queries = questions;
        message.error_flags |= error_flags;

        let (input, (answers, error_flags)) =
            Answer::parse_answers(input, reference_bytes, message.header.ancount.into())?;
        message.answers = answers;
        message.error_flags |= error_flags;

        let (input, (nameservers, error_flags)) =
            Answer::parse_answers(input, reference_bytes, message.header.nscount.into())?;
        message.nameservers = nameservers;
        message.error_flags |= error_flags;

        let (input, (additionals, error_flags)) =
            Answer::parse_additionals(input, reference_bytes, message.header.arcount.into())?;
        message.additional = additionals;
        message.error_flags |= error_flags;

        Ok((input, Some(message)))
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::type_complexity)]
    use crate::enums::*;
    use crate::rdata::*;
    use crate::{
        Answer, Dns, ErrorFlags, Header, Message, OpCode, Parse, QueryResponse, Question,
        RecordClass, RecordType, ResponseCode,
    };
    use rstest::rstest;
    use sawp::error::{Error, Result};
    use sawp::parser::Direction;
    use sawp_flags::Flag;

    #[rstest(
    input,
    expected,
    case::parse_too_long_name(
        &[
            0x31, 0x21, // Transaction ID: 0x3121
            0x81, 0x00, // Flags: response, recursion desired
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65,
            0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x08, 0x73, 0x74, 0x65, 0x72, 0x6c,
            0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65, 0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e,
            0x65, 0x74, 0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72,
            0x65, 0x65, 0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x08, 0x73, 0x74, 0x65,
            0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65, 0x6e, 0x6f, 0x64, 0x65,
            0x03, 0x6e, 0x65, 0x74, 0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08,
            0x66, 0x72, 0x65, 0x65, 0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x08, 0x73,
            0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65, 0x6e, 0x6f,
            0x64, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e,
            0x67, 0x08, 0x66, 0x72, 0x65, 0x65, 0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74,
            0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65,
            0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x08, 0x73, 0x74, 0x65, 0x72, 0x6c,
            0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65, 0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e,
            0x65, 0x74, 0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72,
            0x65, 0x65, 0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x08, 0x73, 0x74, 0x65,
            0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65, 0x6e, 0x6f, 0x64, 0x65,
            0x03, 0x6e, 0x65, 0x74, 0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08,
            0x66, 0x72, 0x65, 0x65, 0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x08, 0x73,
            0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65, 0x6e, 0x6f,
            0x64, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e,
            0x67, 0x08, 0x66, 0x72, 0x65, 0x65, 0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74,
            0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65,
            0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x08, 0x73, 0x74, 0x65, 0x72, 0x6c,
            0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65, 0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e,
            0x65, 0x74, 0x00, // question: sterling.freenode.net (repeated for length)
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0xc0, 0x0c, // answer: sterling.freenode.net
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x27, 0x10, // TTL: 10000
            0x00, 0x04, // Data length: 4
            0xd4, 0xcc, 0xd6, 0x72, // 212.204.214.114
        ],
        Ok((
            0,
            Some(
                Message {
                    header: Header {
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
                    queries: vec ! [
                        Question {
                            name:
                                b"sterling.freenode.net\
                                .sterling.freenode.net\
                                .sterling.freenode.net\
                                .sterling.freenode.net\
                                .sterling.freenode.net\
                                .sterling.freenode.net\
                                .sterling.freenode.net\
                                .sterling.freenode.net\
                                .sterling.freenode.net\
                                .sterling.freenode.net\
                                .sterling.freenode.net\
                                .sterling.free".to_vec(),
                            record_type: RecordType::A,
                            record_type_raw: 1,
                            record_class: RecordClass::IN,
                            record_class_raw: 1,
                        }
                    ],
                    nameservers: vec ! [],
                    answers: vec ! [
                        Answer {
                            name:
                            b"sterling.freenode.net\
                            .sterling.freenode.net\
                            .sterling.freenode.net\
                            .sterling.freenode.net\
                            .sterling.freenode.net\
                            .sterling.freenode.net\
                            .sterling.freenode.net\
                            .sterling.freenode.net\
                            .sterling.freenode.net\
                            .sterling.freenode.net\
                            .sterling.freenode.net\
                            .sterling.free".to_vec(),
                            rtype: RecordType::A,
                            rtype_raw: 1,
                            rclass: RecordClass::IN,
                            rclass_raw: 1,
                            ttl: 10000,
                            data: RDataType::A(vec![212, 204, 214, 114]),
                        }
                    ],
                    additional: vec ! [],
                    error_flags: ErrorFlags::DnsNameExceedsMaxLen.into(),
                }
        )))
    ),
    case::parse_too_long_label(
        &[
            0x31, 0x21, // Transaction ID: 0x3121
            0x81, 0x00, // Flags: response, recursion desired
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x64, // too long
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x00, // question: AAA....
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0xc0, 0x0c, // answer: AAA.....
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x27, 0x10, // TTL: 10000
            0x00, 0x04, // Data length: 4
            0xd4, 0xcc, 0xd6, 0x72, // 212.204.214.114
        ],
        Ok((
        0,
        Some(
        Message {
            header: Header {
                transaction_id: 12577,
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
            queries: vec![
                Question {
                    name: vec![
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    ],
                    record_type: RecordType::A,
                    record_type_raw: 1,
                    record_class: RecordClass::IN,
                    record_class_raw: 1,
                }
            ],
            answers: vec![
                Answer {
                    name: vec![
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    ],
                    rtype: RecordType::A,
                    rtype_raw: 1,
                    rclass: RecordClass::IN,
                    rclass_raw: 1,
                    ttl: 10000,
                    data: RDataType::A(vec![212, 204, 214, 114]),
                }
            ],
            nameservers: vec![],
            additional: vec![],
            error_flags: ErrorFlags::DnsLabelExceedsMaxLen.into(),
        })))
    ),
    case::parse_name_invalid_ptr(
    &[
        0x31, 0x21, // Transaction ID: 0x3121
        0x81, 0x00, // Flags: response, recursion desired
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x01, // ANCOUNT: 1
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65,
        0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74,
        0x00, // question: sterling.freenode.net
        0x00, 0x01, // RType: A
        0x00, 0x01, // RClass: IN
        0xc0, 0xfc, // answer: invalid ptr
        0x00, 0x01, // RType: A
        0x00, 0x01, // RClass: IN
        0x00, 0x00, 0x27, 0x10, // TTL: 10000
        0x00, 0x04, // Data length: 4
        0xd4, 0xcc, 0xd6, 0x72, // 212.204.214.114
    ],
    Ok((
    0,
    Some(
        Message {
            header: Header {
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
            queries: vec![
                Question {
                    name: b"sterling.freenode.net".to_vec(),
                    record_type: RecordType::A,
                    record_type_raw: 1,
                    record_class: RecordClass::IN,
                    record_class_raw: 1,
                }
            ],
            nameservers: vec![],
            answers: vec![
                Answer {
                    name: vec![],
                    rtype: RecordType::A,
                    rtype_raw: 1,
                    rclass: RecordClass::IN,
                    rclass_raw: 1,
                    ttl: 10000,
                    data: RDataType::A(vec![212, 204, 214, 114]),
                }
            ],
            additional: vec![],
            error_flags: ErrorFlags::DnsNameInvalidCompression.into(),
    }
    )))
    ),
    case::parse_bad_record_type(
    &[
        0x31, 0x21, // Transaction ID: 0x3121
        0x81, 0x00, // Flags: response, recursion desired
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x01, // ANCOUNT: 1
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65,
        0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74,
        0x00, // question: sterling.freenode.net
        0x01, 0x05, // RType: UNKNOWN
        0x00, 0x01, // RClass: IN
        0xc0, 0x0c, // answer: sterling.freenode.net
        0x00, 0x01, // RType: A
        0x00, 0x01, // RClass: IN
        0x00, 0x00, 0x27, 0x10, // TTL: 10000
        0x00, 0x04, // Data length: 4
        0xd4, 0xcc, 0xd6, 0x72, // 212.204.214.114
    ],
    Ok((
        0,
        Some(
            Message {
            header: Header {
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
            queries: vec![
                Question {
                    name: b"sterling.freenode.net".to_vec(),
                    record_type: RecordType::UNKNOWN,
                    record_type_raw: 261,
                    record_class: RecordClass::IN,
                    record_class_raw: 1,
                }
            ],
            nameservers: vec![],
            answers: vec![
                Answer {
                    name: b"sterling.freenode.net".to_vec(),
                    rtype: RecordType::A,
                    rtype_raw: 1,
                    rclass: RecordClass::IN,
                    rclass_raw: 1,
                    ttl: 10000,
                    data: (RDataType::A(vec![212, 204, 214, 114])),
                }
            ],
            additional: vec![],
            error_flags: ErrorFlags::UnknownRtype.into(),
            }
    )))
    ),
    case::parse_bad_record_class(
        &[
            0x31, 0x21, // Transaction ID: 0x3121
            0x81, 0x00, // Flags: response, recursion desired
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65,
            0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74,
            0x00, // question: sterling.freenode.net
            0x00, 0x01, // RType: A
            0x00, 0x20, // RClass: UNKNOWN
            0xc0, 0x0c, // answer: sterling.freenode.net
            0x00, 0x01, // RType: A
            0x00, 0x60, // RClass: UNKNOWN
            0x00, 0x00, 0x27, 0x10, // TTL: 10000
            0x00, 0x04, // Data length: 4
            0xd4, 0xcc, 0xd6, 0x72, // 212.204.214.114
        ],
        Ok((
        0,
        Some(
            Message {
            header: Header {
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
            queries: vec![
                Question {
                    name: b"sterling.freenode.net".to_vec(),
                    record_type: RecordType::A,
                    record_type_raw: 1,
                    record_class: RecordClass::UNKNOWN,
                    record_class_raw: 32,
                }
            ],
            nameservers: vec![],
            answers: vec![
                Answer {
                    name: b"sterling.freenode.net".to_vec(),
                    rtype: RecordType::A,
                    rtype_raw: 1,
                    rclass: RecordClass::UNKNOWN,
                    rclass_raw: 96,
                    ttl: 10000,
                    data: (RDataType::A(vec![212, 204, 214, 114])),
                }
            ],
            additional: vec![],
            error_flags: ErrorFlags::UnknownRclass.into(),
            }
        )))
    ),
    case::parse_a_response(
        &[
            0x31, 0x21, // Transaction ID: 0x3121
            0x81, 0x00, // Flags: response, recursion desired
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65,
            0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74,
            0x00, // question: sterling.freenode.net
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0xc0, 0x0c, // answer: sterling.freenode.net
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x27, 0x10, // TTL: 10000
            0x00, 0x04, // Data length: 4
            0xd4, 0xcc, 0xd6, 0x72, // 212.204.214.114
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
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
                queries: vec![
                    Question {
                        name: b"sterling.freenode.net".to_vec(),
                        record_type: RecordType::A,
                        record_type_raw: 1,
                        record_class: RecordClass::IN,
                        record_class_raw: 1,
                    }
                ],
                nameservers: vec![],
                answers: vec![
                    Answer {
                        name: b"sterling.freenode.net".to_vec(),
                        rtype: RecordType::A,
                        rtype_raw: 1,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 10000,
                        data: (RDataType::A(vec![212, 204, 214, 114])),
                    }
                ],
                additional: vec![],
                error_flags: ErrorFlags::none(),
            }
        )))
    ),
    case::parse_txt_response(
        &[
            0x10, 0x32, // Transaction ID: 0x1032
            0x81, 0x80, // Flags: response, recursion desired, recursion available
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            // question: google.com
            0x00, 0x10, // RType: TXT
            0x00, 0x01, // RCLASS: IN
            0xc0, 0x0c, // answer: google.com
            0x00, 0x10, // RType: TXT
            0x00, 0x01, // RCLASS: IN
            0x00, 0x00, 0x01, 0x0e, // TTL: 270
            0x00, 0x10, // Data length: 15
            0x0f, 0x76, 0x3d, 0x73, 0x70, 0x66, 0x31, 0x20, 0x70, 0x74, 0x72, 0x20, 0x3f, 0x61,
            0x6c, 0x6c, // v=spf1 ptr ?all
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
                    transaction_id: 0x1032,
                    flags: 0b1000_0001_1000_0000,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::QUERY,
                    authoritative: false,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: true,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NOERROR,
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0,
                },
                queries: vec![
                    Question {
                        name: b"google.com".to_vec(),
                        record_type: RecordType::TXT,
                        record_type_raw: 16,
                        record_class: RecordClass::IN,
                        record_class_raw: 1,
                    }
                ],
                answers: vec![
                    Answer {
                        name: b"google.com".to_vec(),
                        rtype: RecordType::TXT,
                        rtype_raw: 16,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 270,
                        data: (RDataType::TXT(b"v=spf1 ptr ?all".to_vec())),
                    }
                ],
                nameservers: vec![],
                additional: vec![],
                error_flags: ErrorFlags::none(),
            }
        )))
    ),
    case::parse_mx_response_with_additional_records(
        &[
            0xf7, 0x6f, // Transaction ID: 0xf76f
            0x81, 0x80, // Flags: response, recursion desired, recursion available
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x06, // ANCOUNT: 6
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x06, // ARCOUNT: 0
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            // question: google.com
            0x00, 0x0f, // RType: MX
            0x00, 0x01, // RClass: IN
            0xc0, 0x0c, // answer: google.com
            0x00, 0x0f, // RType: MX
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x28, // TTL: 552
            0x00, 0x0a, // Data length: 10
            0x00, 0x28, // Preference: 40
            0x05, 0x73, 0x6d, 0x74, 0x70, 0x34, 0xc0, 0x0c, // MX: smtp4.google.com
            0xc0, 0x0c, // answer: google.com
            0x00, 0x0f, // RType: MX
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x28, // TTL: 552
            0x00, 0x0a, // Data length: 10
            0x00, 0x0a, // Preference: 10
            0x05, 0x73, 0x6d, 0x74, 0x70, 0x35, 0xc0, 0x0c, // MX: smtp5.google.com
            0xc0, 0x0c, // answer: google.com
            0x00, 0x0f, // RType: MX
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x28, // TTL: 552
            0x00, 0x0a, // Data length: 10
            0x00, 0x0a, // Preference: 10
            0x05, 0x73, 0x6d, 0x74, 0x70, 0x36, 0xc0, 0x0c, // MX: smtp6.google.com
            0xc0, 0x0c, // answer: google.com
            0x00, 0x0f, // RType: MX
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x28, // TTL: 552
            0x00, 0x0a, // Data length: 10
            0x00, 0x0a, // Preference: 10
            0x05, 0x73, 0x6d, 0x74, 0x70, 0x31, 0xc0, 0x0c, // MX: smtp1.google.com
            0xc0, 0x0c, // answer: google.com
            0x00, 0x0f, // RType: MX
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x28, // TTL: 552
            0x00, 0x0a, // Data length: 10
            0x00, 0x0a, // Preference: 10
            0x05, 0x73, 0x6d, 0x74, 0x70, 0x32, 0xc0, 0x0c, // MX: smtp2.google.com
            0xc0, 0x0c, // answer: google.com
            0x00, 0x0f, // RType: MX
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x28, // TTL: 552
            0x00, 0x0a, // Data length: 10
            0x00, 0x28, // Preference: 10
            0x05, 0x73, 0x6d, 0x74, 0x70, 0x33, 0xc0, 0x0c, // MX: smtp3.google.com
            0xc0, 0x2a, // additional: smtp4.google.com
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x58, // TTL: 600
            0x00, 0x04, // Data length: 4
            0xd8, 0xef, 0x25, 0x1a, // 216.239.37.26
            0xc0, 0x40, // additional: smtp5.google.com
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x58, // TTL: 600
            0x00, 0x04, // Data length: 4
            0x40, 0xe9, 0xa7, 0x19, // 64.233.167.25
            0xc0, 0x56, // additional: smtp6.google.com
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x58, // TTL: 600
            0x00, 0x04, // Data length: 4
            0x42, 0x66, 0x09, 0x19, // 66.102.9.25
            0xc0, 0x6c, // additional: smtp1.google.com
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x58, // TTL: 600
            0x00, 0x04, // Data length: 4
            0xd8, 0xef, 0x39, 0x19, // 216.239.57.25
            0xc0, 0x82, // additional: smtp2.google.com
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x58, // TTL: 600
            0x00, 0x04, // Data length: 4
            0xd8, 0xef, 0x25, 0x19, // 216.239.37.25
            0xc0, 0x98, // additional: smtp2.google.com
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x58, // TTL: 600
            0x00, 0x04, // Data length: 4
            0xd8, 0xef, 0x39, 0x1a, // 216.239.57.26
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
                    transaction_id: 0xf76f,
                    flags: 0b1000_0001_1000_0000,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::QUERY,
                    authoritative: false,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: true,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NOERROR,
                    qdcount: 1,
                    ancount: 6,
                    nscount: 0,
                    arcount: 6,
                },
                queries: vec![
                    Question {
                        name: b"google.com".to_vec(),
                        record_type: RecordType::MX,
                        record_type_raw: 15,
                        record_class: RecordClass::IN,
                        record_class_raw: 1,
                    }
                ],
                answers: vec![
                    Answer {
                        name: b"google.com".to_vec(),
                        rtype: RecordType::MX,
                        rtype_raw: 15,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 552,
                        data: (RDataType::MX(b"smtp4.google.com".to_vec())),
                    },
                    Answer {
                        name: b"google.com".to_vec(),
                        rtype: RecordType::MX,
                        rtype_raw: 15,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 552,
                        data: (RDataType::MX(b"smtp5.google.com".to_vec())),
                    },
                    Answer {
                        name: b"google.com".to_vec(),
                        rtype: RecordType::MX,
                        rtype_raw: 15,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 552,
                        data: (RDataType::MX(b"smtp6.google.com".to_vec())),
                    },
                    Answer {
                        name: b"google.com".to_vec(),
                        rtype: RecordType::MX,
                        rtype_raw: 15,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 552,
                        data: (RDataType::MX(b"smtp1.google.com".to_vec())),
                    },
                    Answer {
                        name: b"google.com".to_vec(),
                        rtype: RecordType::MX,
                        rtype_raw: 15,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 552,
                        data: (RDataType::MX(b"smtp2.google.com".to_vec())),
                    },
                    Answer {
                        name: b"google.com".to_vec(),
                        rtype: RecordType::MX,
                        rtype_raw: 15,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 552,
                        data: (RDataType::MX(b"smtp3.google.com".to_vec())),
                    },
                ],
                nameservers: vec![],
                additional: vec![
                    Answer {
                        name: b"smtp4.google.com".to_vec(),
                        rtype: RecordType::A,
                        rtype_raw: 1,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 600,
                        data: (RDataType::A(vec![216, 239, 37, 26])),
                    },
                    Answer {
                        name: b"smtp5.google.com".to_vec(),
                        rtype: RecordType::A,
                        rtype_raw: 1,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 600,
                        data: (RDataType::A(vec![64, 233, 167, 25])),
                    },
                    Answer {
                        name: b"smtp6.google.com".to_vec(),
                        rtype: RecordType::A,
                        rtype_raw: 1,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 600,
                        data: (RDataType::A(vec![66, 102, 9, 25])),
                    },
                    Answer {
                        name: b"smtp1.google.com".to_vec(),
                        rtype: RecordType::A,
                        rtype_raw: 1,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 600,
                        data: (RDataType::A(vec![216, 239, 57, 25])),
                    },
                        Answer {
                        name: b"smtp2.google.com".to_vec(),
                        rtype: RecordType::A,
                        rtype_raw: 1,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 600,
                        data: (RDataType::A(vec![216, 239, 37, 25])),
                    },
                    Answer {
                        name: b"smtp3.google.com".to_vec(),
                        rtype: RecordType::A,
                        rtype_raw: 1,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 600,
                        data: (RDataType::A(vec![216, 239, 57, 26])),
                    },
                ],
                error_flags: ErrorFlags::none(),
            }
        )))
    ),
    case::parse_loc_response(
        &[
            0x49, 0xa1, // Transaction ID: 0x49a1
            0x81, 0x80, // Flags: response, recursion desired, recursion available
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            // question: google.com
            0x00, 0x1d, // RType: LOC
            0x00, 0x01, // RClass: IN
        ],
        Ok((
            0,
            Some(
                Message {
                    header: Header {
                        transaction_id: 0x49a1,
                        flags: 0b1000_0001_1000_0000,
                        query_response: QueryResponse::Response,
                        opcode: OpCode::QUERY,
                        authoritative: false,
                        truncated: false,
                        recursion_desired: true,
                        recursion_available: true,
                        zflag: false,
                        authenticated_data: false,
                        check_disabled: false,
                        rcode: ResponseCode::NOERROR,
                        qdcount: 1,
                        ancount: 0,
                        nscount: 0,
                        arcount: 0,
                    },
                    queries: vec![
                        Question {
                            name: b"google.com".to_vec(),
                            record_type: RecordType::LOC,
                            record_type_raw: 29,
                            record_class: RecordClass::IN,
                            record_class_raw: 1,
                        }
                    ],
                    answers: vec![],
                    nameservers: vec![],
                    additional: vec![],
                    error_flags: ErrorFlags::none(),
                }
        )))
    ),
    case::parse_ptr_response(
        &[
            0x9b, 0xbb, // Transaction ID: 0x9bbb
            0x81, 0x80, // Flags: response, recursion desired, recursion available
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x03, 0x31, 0x30, 0x34, 0x01, 0x39, 0x03, 0x31, 0x39, 0x32, 0x02, 0x36, 0x36, 0x07,
            0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00,
            // question: 104.9.192.66.in-addr.arpa
            0x00, 0x0c, // RType: PTR
            0x00, 0x01, // RClass: IN
            0xc0, 0x0c, // answer: 104.9.192.66.in-addr.arpa
            0x00, 0x0c, // RType: PTR
            0x00, 0x01, // RClass: IN
            0x00, 0x01, 0x51, 0x25, // TTL: 86309
            0x00, 0x20, 0x0c, 0x36, // Data length: 32
            0x36, 0x2d, 0x31, 0x39, 0x32, 0x2d, 0x39, 0x2d, 0x31, 0x30, 0x34, 0x03, 0x67, 0x65,
            0x6e, 0x09, 0x74, 0x77, 0x74, 0x65, 0x6c, 0x65, 0x63, 0x6f, 0x6d, 0x03, 0x6e, 0x65,
            0x74, 0x00, // 66-192-9-104.gen.twtelecom.net
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
                    transaction_id: 0x9bbb,
                    flags: 0b1000_0001_1000_0000,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::QUERY,
                    authoritative: false,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: true,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NOERROR,
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0,
                },
                queries: vec![
                    Question {
                        name: b"104.9.192.66.in-addr.arpa".to_vec(),
                        record_type: RecordType::PTR,
                        record_type_raw: 12,
                        record_class: RecordClass::IN,
                        record_class_raw: 1,
                    }
                ],
                answers: vec![
                    Answer {
                        name: b"104.9.192.66.in-addr.arpa".to_vec(),
                        rtype: RecordType::PTR,
                        rtype_raw: 12,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 86309,
                        data: (RDataType::PTR(b"66-192-9-104.gen.twtelecom.net".to_vec())),
                    }
                ],
                nameservers: vec![],
                additional: vec![],
                error_flags: ErrorFlags::none(),
            }
        )))
    ),
    case::parse_aaaa_response(
        &[
            0xf0, 0xd4, // Transaction ID: 0xf0d4
            0x81, 0x80, // Flags: response, recursion desired, recursion available
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x03, 0x77, 0x77, 0x77, 0x06, 0x6e, 0x65, 0x74, 0x62, 0x73, 0x64, 0x03, 0x6f, 0x72,
            0x67, 0x00, // question: www.netbsd.org
            0x00, 0x1c, // RType: AAAA
            0x00, 0x01, // RClass: IN
            0xc0, 0x0c, // answer: www.netbsd.org
            0x00, 0x1c, // RType: AAAA
            0x00, 0x01, // RClass: IN
            0x00, 0x01, 0x51, 0x80, // TTL: 86400
            0x00, 0x10, // Data length: 16
            0x20, 0x01, 0x04, 0xf8, 0x00, 0x04, 0x00, 0x07, 0x02, 0xe0, 0x81, 0xff, 0xfe, 0x52,
            0x9a, 0x6b, // 2001:4f8:4:7:2e0:81ff:fe52:9a6b
        ],
        Ok((
            0,
            Some(
            Message {
                header: Header {
                    transaction_id: 0xf0d4,
                    flags: 0b1000_0001_1000_0000,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::QUERY,
                    authoritative: false,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: true,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NOERROR,
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0,
                },
                queries: vec![
                    Question {
                        name: b"www.netbsd.org".to_vec(),
                        record_type: RecordType::AAAA,
                        record_type_raw: 28,
                        record_class: RecordClass::IN,
                        record_class_raw: 1,
                }],
                answers: vec![
                    Answer {
                        name: b"www.netbsd.org".to_vec(),
                        rtype: RecordType::AAAA,
                        rtype_raw: 28,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 86400,
                        data: (RDataType::AAAA(vec![
                        0x20, 0x01, 0x04, 0xf8, 0x00, 0x04, 0x00, 0x07, 0x02, 0xe0, 0x81, 0xff, 0xfe,
                        0x52, 0x9a, 0x6b,
                    ])),
                }],
                nameservers: vec![],
                additional: vec![],
                error_flags: ErrorFlags::none(),
            }
        )))
    ),
    case::parse_cname_response(
        &[
        0x8d, 0xb3, // Transaction ID: 0x8db3
        0x81, 0x80, // Flags: response, recursion desired, recursion available
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x01, // ANCOUNT: 1
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f,
        0x6d, 0x00, // question: www.google.com
        0x00, 0x1c, // RType: AAAA
        0x00, 0x01, // RClass: IN
        0xc0, 0x0c, // answer: www.google.com
        0x00, 0x05, // RType: CNAME
        0x00, 0x01, // RClass: IN
        0x00, 0x00, 0x02, 0x79, // TTL: 633
        0x00, 0x08, 0x03, 0x77, 0x77, 0x77, 0x01, 0x6c, 0xc0, 0x10, // www.l.google.com
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
                    transaction_id: 0x8db3,
                    flags: 0b1000_0001_1000_0000,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::QUERY,
                    authoritative: false,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: true,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NOERROR,
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0,
                },
                queries: vec![
                    Question {
                        name: b"www.google.com".to_vec(),
                        record_type: RecordType::AAAA,
                        record_type_raw: 28,
                        record_class: RecordClass::IN,
                        record_class_raw: 1,
                    }
                ],
                answers: vec![
                    Answer {
                        name: b"www.google.com".to_vec(),
                        rtype: RecordType::CNAME,
                        rtype_raw: 5,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 633,
                        data: (RDataType::CNAME(b"www.l.google.com".to_vec())),
                    }
                ],
                nameservers: vec![],
                additional: vec![],
                error_flags: ErrorFlags::none(),
            }
        )))
    ),
    case::parse_error_response_no_such_name(
        &[
            0x26, 0x6d, // Transaction ID: 0x266d
            0x85,
            0x83, // Flags: response, authenticated data, recursion desired, recursion available, NAMEERROR
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x07, 0x6e,
            0x6f, 0x74, 0x67, 0x69, 0x6e, 0x68, 0x00, // question: www.example.notginh
            0x00, 0x1c, // RType: AAAA
            0x00, 0x01, // RClass: IN
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
                    transaction_id: 0x266d,
                    flags: 0b1000_0101_1000_0011,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::QUERY,
                    authoritative: true,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: true,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NAMEERROR,
                    qdcount: 1,
                    ancount: 0,
                    nscount: 0,
                    arcount: 0,
                },
                queries: vec![
                    Question {
                        name: b"www.example.notginh".to_vec(),
                        record_type: RecordType::AAAA,
                        record_type_raw: 28,
                        record_class: RecordClass::IN,
                        record_class_raw: 1,
                    }
                ],
                answers: vec![],
                nameservers: vec![],
                additional: vec![],
                error_flags: ErrorFlags::none(),
            }
        )))
    ),
    case::parse_any_response(
        &[
            0xfe, 0xe3, // Transaction ID: 0xfee3
            0x81, 0x80, // Flags: response, recursion desired, recursion available
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x02, // ANCOUNT: 2
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x03, 0x77, 0x77, 0x77, 0x03, 0x69, 0x73, 0x63, 0x03, 0x6f, 0x72, 0x67, 0x00,
            // question: www.isc.org
            0x00, 0xff, // RType: ANY
            0x00, 0x01, // RClass: IN
            0xc0, 0x0c, // answer: www.isc.org
            0x00, 0x1c, // RType: AAAA
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x58, // TTL: 600
            0x00, 0x10, // Data length: 16
            0x20, 0x01, 0x04, 0xf8, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x0d, // 2001:4f8:0:2::d
            0xc0, 0x0c, // answer: www.isc.org
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x02, 0x58, // TTL: 600
            0x00, 0x04, // Data length: 4
            0xcc, 0x98, 0xb8, 0x58, // 204.152.184.88
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
                    transaction_id: 0xfee3,
                    flags: 0b1000_0001_1000_0000,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::QUERY,
                    authoritative: false,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: true,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NOERROR,
                    qdcount: 1,
                    ancount: 2,
                    nscount: 0,
                    arcount: 0,
                },
                queries: vec![
                    Question {
                        name: b"www.isc.org".to_vec(),
                        record_type: RecordType::ANY,
                        record_type_raw: 255,
                        record_class: RecordClass::IN,
                        record_class_raw: 1,
                    }
                ],
                answers: vec![
                    Answer {
                        name: b"www.isc.org".to_vec(),
                        rtype: RecordType::AAAA,
                        rtype_raw: 28,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 600,
                        data: (RDataType::AAAA(vec![
                        0x20, 0x01, 0x04, 0xf8, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x0d,
                        ])),
                    },
                    Answer {
                        name: b"www.isc.org".to_vec(),
                        rtype: RecordType::A,
                        rtype_raw: 1,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 600,
                        data: (RDataType::A(vec![0xcc, 0x98, 0xb8, 0x58])),
                    },
                ],
                nameservers: vec![],
                additional: vec![],
                error_flags: ErrorFlags::none(),
            }
        )))
    ),
    case::parse_ns_response(
        &[
            0x20, 0x8a, // Transaction ID: 0x208a
            0x81, 0x80, // Flags: response, recursion desired, recursion available
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x04, // ANCOUNT: 4
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x03, 0x69, 0x73, 0x63, 0x03, 0x6f, 0x72, 0x67, 0x00, // question: isc.org
            0x00, 0x02, // RType: NS
            0x00, 0x01, // RClass: IN
            0xc0, 0x0c, // answer: isc.org
            0x00, 0x02, // RType: NS
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x0e, // Data length: 14
            0x06, 0x6e, 0x73, 0x2d, 0x65, 0x78, 0x74, 0x04, 0x6e, 0x72, 0x74, 0x31, 0xc0, 0x0c,
            // ns-ext.nrt1.isc.org
            0xc0, 0x0c, // answer: isc.org
            0x00, 0x02, // RType: NS
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x0e, // Data length: 14
            0x06, 0x6e, 0x73, 0x2d, 0x65, 0x78, 0x74, 0x04, 0x73, 0x74, 0x68, 0x31, 0xc0, 0x0c,
            // ns-ext.sth1.isc.org
            0xc0, 0x0c, // answer: isc.org
            0x00, 0x02, // RType: NS
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x09, // Data length: 9
            0x06, 0x6e, 0x73, 0x2d, 0x65, 0x78, 0x74, 0xc0, 0x0c, // ns-ext.isc.org
            0xc0, 0x0c, // answer: isc.org
            0x00, 0x02, // RType: NS
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x0e, // Data length: 14
            0x06, 0x6e, 0x73, 0x2d, 0x65, 0x78, 0x74, 0x04, 0x6c, 0x67, 0x61, 0x31, 0xc0,
            0x0c, // ns-ext.lga1.isc.org
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
                    transaction_id: 0x208a,
                    flags: 0b1000_0001_1000_0000,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::QUERY,
                    authoritative: false,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: true,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NOERROR,
                    qdcount: 1,
                    ancount: 4,
                    nscount: 0,
                    arcount: 0,
                },
                queries: vec![
                    Question {
                        name: b"isc.org".to_vec(),
                        record_type: RecordType::NS,
                        record_type_raw: 2,
                        record_class: RecordClass::IN,
                        record_class_raw: 1,
                    }
                ],
                answers: vec![
                    Answer {
                        name: b"isc.org".to_vec(),
                        rtype: RecordType::NS,
                        rtype_raw: 2,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 3600,
                        data: (RDataType::NS(b"ns-ext.nrt1.isc.org".to_vec())),
                    },
                    Answer {
                        name: b"isc.org".to_vec(),
                        rtype: RecordType::NS,
                        rtype_raw: 2,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 3600,
                        data: (RDataType::NS(b"ns-ext.sth1.isc.org".to_vec())),
                    },
                    Answer {
                        name: b"isc.org".to_vec(),
                        rtype: RecordType::NS,
                        rtype_raw: 2,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 3600,
                        data: (RDataType::NS(b"ns-ext.isc.org".to_vec())),
                    },
                    Answer {
                        name: b"isc.org".to_vec(),
                        rtype: RecordType::NS,
                        rtype_raw: 2,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 3600,
                        data: (RDataType::NS(b"ns-ext.lga1.isc.org".to_vec())),
                    },
                ],
                nameservers: vec![],
                additional: vec![],
                error_flags: ErrorFlags::none(),
            }
        )))
    ),
    case::parse_large_txt_response(
        &[
            0xd3, 0x88, // Transaction ID: 0xd388
            0x81, 0x80, // Flags: response, recursion desired, recursion available
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x08, 0x6d, 0x69, 0x6d, 0x69, 0x6b, 0x61, 0x74, 0x7a, 0x02, 0x32, 0x31, 0x0b, 0x70,
            0x61, 0x63, 0x6b, 0x65, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x03, 0x63, 0x6f, 0x6d,
            0x00, // question: mimikatz.21.packetclass.com
            0x00, 0x10, // RType: TXT
            0x00, 0x01, // RClass: IN
            0xc0, 0x0c, // answer: mimikatz.21.packetclass.com
            0x00, 0x10, // RType: TXT
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x00, 0x3b, // TTL: 59
            0x04, 0x25, // Data length: 1061
            0xfa, // TXT length: 250
            0x78, 0x68, 0x44, 0x68, 0x73, 0x48, 0x50, 0x45, 0x6a, 0x31, 0x71, 0x44, 0x72, 0x50,
            0x62, 0x47, 0x63, 0x70, 0x54, 0x35, 0x63, 0x6e, 0x66, 0x2f, 0x41, 0x64, 0x55, 0x68,
            0x4d, 0x59, 0x49, 0x43, 0x2f, 0x44, 0x43, 0x43, 0x41, 0x76, 0x67, 0x43, 0x41, 0x51,
            0x45, 0x77, 0x67, 0x5a, 0x4d, 0x77, 0x66, 0x6a, 0x45, 0x4c, 0x4d, 0x41, 0x6b, 0x47,
            0x41, 0x31, 0x55, 0x45, 0x42, 0x68, 0x4d, 0x43, 0x55, 0x45, 0x77, 0x78, 0x49, 0x6a,
            0x41, 0x67, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x6f, 0x54, 0x47, 0x56, 0x56, 0x75,
            0x61, 0x58, 0x70, 0x6c, 0x64, 0x47, 0x38, 0x67, 0x56, 0x47, 0x56, 0x6a, 0x61, 0x47,
            0x35, 0x76, 0x62, 0x47, 0x39, 0x6e, 0x61, 0x57, 0x56, 0x7a, 0x49, 0x46, 0x4d, 0x75,
            0x51, 0x53, 0x34, 0x78, 0x4a, 0x7a, 0x41, 0x6c, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41,
            0x73, 0x54, 0x48, 0x6b, 0x4e, 0x6c, 0x63, 0x6e, 0x52, 0x31, 0x62, 0x53, 0x42, 0x44,
            0x5a, 0x58, 0x4a, 0x30, 0x61, 0x57, 0x5a, 0x70, 0x59, 0x32, 0x46, 0x30, 0x61, 0x57,
            0x39, 0x75, 0x49, 0x45, 0x46, 0x31, 0x64, 0x47, 0x68, 0x76, 0x63, 0x6d, 0x6c, 0x30,
            0x65, 0x54, 0x45, 0x69, 0x4d, 0x43, 0x41, 0x47, 0x41, 0x31, 0x55, 0x45, 0x41, 0x78,
            0x4d, 0x5a, 0x51, 0x32, 0x56, 0x79, 0x64, 0x48, 0x56, 0x74, 0x49, 0x46, 0x52, 0x79,
            0x64, 0x58, 0x4e, 0x30, 0x5a, 0x57, 0x51, 0x67, 0x54, 0x6d, 0x56, 0x30, 0x64, 0x32,
            0x39, 0x79, 0x61, 0x79, 0x42, 0x44, 0x51, 0x51, 0x49, 0x52, 0x41, 0x50, 0x35, 0x6e,
            0x35, 0x50, 0x46, 0x61, 0x4a, 0x4f, 0x50, 0x47, 0x44, 0x56, 0x52, 0x38, 0x6f, 0x43,
            0x44, 0x43, 0x64, 0x6e, 0x41, 0x77, 0x44, 0x51, 0x59, 0x4a, 0x59, 0x49, // TXT
            0xfa, // TXT length: 250
            0x5a, 0x49, 0x41, 0x57, 0x55, 0x44, 0x42, 0x41, 0x49, 0x42, 0x42, 0x51, 0x43, 0x67,
            0x67, 0x67, 0x45, 0x35, 0x4d, 0x42, 0x6f, 0x47, 0x43, 0x53, 0x71, 0x47, 0x53, 0x49,
            0x62, 0x33, 0x44, 0x51, 0x45, 0x4a, 0x41, 0x7a, 0x45, 0x4e, 0x42, 0x67, 0x73, 0x71,
            0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x43, 0x52, 0x41, 0x42, 0x42, 0x44,
            0x41, 0x63, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42,
            0x43, 0x51, 0x55, 0x78, 0x44, 0x78, 0x63, 0x4e, 0x4d, 0x54, 0x6b, 0x77, 0x4e, 0x7a,
            0x45, 0x77, 0x4d, 0x6a, 0x45, 0x78, 0x4d, 0x54, 0x45, 0x7a, 0x57, 0x6a, 0x41, 0x76,
            0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x43, 0x51,
            0x51, 0x78, 0x49, 0x67, 0x51, 0x67, 0x52, 0x55, 0x44, 0x4c, 0x4e, 0x54, 0x6f, 0x68,
            0x36, 0x2b, 0x74, 0x6a, 0x2f, 0x6b, 0x39, 0x7a, 0x47, 0x54, 0x6d, 0x44, 0x39, 0x76,
            0x65, 0x65, 0x32, 0x6a, 0x43, 0x38, 0x78, 0x6b, 0x5a, 0x53, 0x68, 0x31, 0x4a, 0x64,
            0x43, 0x39, 0x47, 0x6a, 0x53, 0x61, 0x49, 0x77, 0x67, 0x63, 0x73, 0x47, 0x43, 0x79,
            0x71, 0x47, 0x53, 0x49, 0x62, 0x33, 0x44, 0x51, 0x45, 0x4a, 0x45, 0x41, 0x49, 0x4d,
            0x4d, 0x59, 0x47, 0x37, 0x4d, 0x49, 0x47, 0x34, 0x4d, 0x49, 0x47, 0x31, 0x4d, 0x49,
            0x47, 0x79, 0x42, 0x42, 0x52, 0x50, 0x6a, 0x55, 0x78, 0x49, 0x42, 0x6b, 0x6c, 0x43,
            0x61, 0x75, 0x2b, 0x4c, 0x68, 0x74, 0x54, 0x56, 0x2f, 0x48, 0x6b, 0x79, 0x35, 0x78,
            0x51, 0x74, 0x68, 0x54, 0x43, 0x42, 0x6d, 0x54, 0x43, 0x42, 0x67, 0x36, 0x53, 0x42,
            0x67, 0x44, 0x42, 0x2b, 0x4d, 0x51, 0x73, 0x77, 0x43, 0x51, 0x59, 0x44, //TXT
            0xfa, // TXT length: 250
            0x56, 0x51, 0x51, 0x47, 0x45, 0x77, 0x4a, 0x51, 0x54, 0x44, 0x45, 0x69, 0x4d, 0x43,
            0x41, 0x47, 0x41, 0x31, 0x55, 0x45, 0x43, 0x68, 0x4d, 0x5a, 0x56, 0x57, 0x35, 0x70,
            0x65, 0x6d, 0x56, 0x30, 0x62, 0x79, 0x42, 0x55, 0x5a, 0x57, 0x4e, 0x6f, 0x62, 0x6d,
            0x39, 0x73, 0x62, 0x32, 0x64, 0x70, 0x5a, 0x58, 0x4d, 0x67, 0x55, 0x79, 0x35, 0x42,
            0x4c, 0x6a, 0x45, 0x6e, 0x4d, 0x43, 0x55, 0x47, 0x41, 0x31, 0x55, 0x45, 0x43, 0x78,
            0x4d, 0x65, 0x51, 0x32, 0x56, 0x79, 0x64, 0x48, 0x56, 0x74, 0x49, 0x45, 0x4e, 0x6c,
            0x63, 0x6e, 0x52, 0x70, 0x5a, 0x6d, 0x6c, 0x6a, 0x59, 0x58, 0x52, 0x70, 0x62, 0x32,
            0x34, 0x67, 0x51, 0x58, 0x56, 0x30, 0x61, 0x47, 0x39, 0x79, 0x61, 0x58, 0x52, 0x35,
            0x4d, 0x53, 0x49, 0x77, 0x49, 0x41, 0x59, 0x44, 0x56, 0x51, 0x51, 0x44, 0x45, 0x78,
            0x6c, 0x44, 0x5a, 0x58, 0x4a, 0x30, 0x64, 0x57, 0x30, 0x67, 0x56, 0x48, 0x4a, 0x31,
            0x63, 0x33, 0x52, 0x6c, 0x5a, 0x43, 0x42, 0x4f, 0x5a, 0x58, 0x52, 0x33, 0x62, 0x33,
            0x4a, 0x72, 0x49, 0x45, 0x4e, 0x42, 0x41, 0x68, 0x45, 0x41, 0x2f, 0x6d, 0x66, 0x6b,
            0x38, 0x56, 0x6f, 0x6b, 0x34, 0x38, 0x59, 0x4e, 0x56, 0x48, 0x79, 0x67, 0x49, 0x4d,
            0x4a, 0x32, 0x63, 0x44, 0x41, 0x4e, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47,
            0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x45, 0x46, 0x41, 0x41, 0x53, 0x43, 0x41, 0x51,
            0x41, 0x77, 0x33, 0x56, 0x52, 0x77, 0x6a, 0x78, 0x4b, 0x31, 0x44, 0x45, 0x33, 0x52,
            0x43, 0x38, 0x51, 0x58, 0x44, 0x61, 0x76, 0x33, 0x57, 0x63, 0x6c, 0x45, 0x5a, 0x56,
            0x67, 0x7a, 0x56, 0x7a, 0x59, 0x7a, 0x45, 0x59, 0x53, 0x4f, 0x6e, 0x4c, // TXT
            0xfa, // TXT length: 250
            0x48, 0x54, 0x4f, 0x4b, 0x49, 0x44, 0x75, 0x2b, 0x4e, 0x51, 0x6a, 0x6e, 0x55, 0x66,
            0x36, 0x4d, 0x68, 0x61, 0x51, 0x51, 0x2f, 0x67, 0x50, 0x4d, 0x52, 0x73, 0x75, 0x55,
            0x6c, 0x35, 0x41, 0x6a, 0x68, 0x64, 0x4a, 0x6a, 0x6f, 0x66, 0x54, 0x6c, 0x46, 0x78,
            0x62, 0x68, 0x66, 0x61, 0x47, 0x4a, 0x4e, 0x47, 0x6f, 0x52, 0x50, 0x4a, 0x55, 0x5a,
            0x53, 0x6a, 0x53, 0x33, 0x53, 0x46, 0x58, 0x63, 0x63, 0x33, 0x6a, 0x48, 0x6d, 0x6e,
            0x35, 0x4e, 0x56, 0x2b, 0x2f, 0x58, 0x69, 0x70, 0x54, 0x33, 0x61, 0x55, 0x2f, 0x48,
            0x56, 0x64, 0x2b, 0x49, 0x41, 0x31, 0x42, 0x55, 0x6c, 0x68, 0x63, 0x43, 0x74, 0x43,
            0x71, 0x4d, 0x53, 0x68, 0x59, 0x2b, 0x56, 0x36, 0x65, 0x31, 0x5a, 0x5a, 0x39, 0x4f,
            0x72, 0x34, 0x4c, 0x5a, 0x79, 0x6b, 0x33, 0x70, 0x6c, 0x65, 0x39, 0x52, 0x7a, 0x6f,
            0x6d, 0x30, 0x42, 0x63, 0x44, 0x32, 0x4f, 0x6e, 0x4c, 0x4f, 0x70, 0x45, 0x7a, 0x51,
            0x72, 0x75, 0x62, 0x44, 0x46, 0x72, 0x36, 0x78, 0x4b, 0x41, 0x45, 0x2f, 0x6d, 0x51,
            0x66, 0x74, 0x41, 0x6e, 0x75, 0x51, 0x36, 0x77, 0x73, 0x71, 0x50, 0x42, 0x58, 0x49,
            0x2f, 0x79, 0x46, 0x36, 0x42, 0x31, 0x62, 0x59, 0x44, 0x36, 0x38, 0x79, 0x41, 0x4e,
            0x6f, 0x64, 0x6a, 0x38, 0x78, 0x71, 0x6d, 0x55, 0x73, 0x33, 0x33, 0x4e, 0x76, 0x4e,
            0x4d, 0x62, 0x2b, 0x32, 0x6f, 0x4e, 0x49, 0x67, 0x4c, 0x71, 0x54, 0x34, 0x65, 0x31,
            0x46, 0x64, 0x4d, 0x6d, 0x72, 0x4f, 0x54, 0x31, 0x41, 0x53, 0x50, 0x76, 0x2f, 0x52,
            0x6a, 0x31, 0x44, 0x54, 0x79, 0x78, 0x64, 0x41, 0x30, 0x4a, 0x44, 0x70, 0x41, 0x45,
            0x46, 0x59, 0x48, 0x6d, 0x35, 0x78, 0x57, 0x4b, 0x33, 0x36, 0x72, 0x38, //TXT
            0x38, // TXT length: 56
            0x35, 0x78, 0x54, 0x63, 0x62, 0x4b, 0x34, 0x48, 0x69, 0x37, 0x54, 0x33, 0x4f, 0x39,
            0x55, 0x76, 0x50, 0x43, 0x72, 0x69, 0x68, 0x70, 0x44, 0x4a, 0x65, 0x70, 0x63, 0x6f,
            0x46, 0x4e, 0x42, 0x69, 0x62, 0x46, 0x6c, 0x59, 0x4f, 0x46, 0x66, 0x6c, 0x6c, 0x59,
            0x57, 0x36, 0x38, 0x58, 0x31, 0x66, 0x72, 0x57, 0x53, 0x6a, 0x41, 0x41, 0x41,
            0x41,
            // TXT
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
                    transaction_id: 0xd388,
                    flags: 0b1000_0001_1000_0000,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::QUERY,
                    authoritative: false,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: true,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NOERROR,
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0,
                },
                queries: vec![
                    Question {
                        name: b"mimikatz.21.packetclass.com".to_vec(),
                        record_type: RecordType::TXT,
                        record_type_raw: 16,
                        record_class: RecordClass::IN,
                        record_class_raw: 1,
                    }
                ],
                answers: vec![
                    Answer {
                        name: b"mimikatz.21.packetclass.com".to_vec(),
                        rtype: RecordType::TXT,
                        rtype_raw: 16,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 59,
                        data: (RDataType::TXT(
                            "xhDhsHPEj1qDrPbGcpT5cnf/AdUhMYIC/DCCAvgCAQEwgZMwfjELMAk\
                            GA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFM\
                            uQS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml\
                            0eTEiMCAGA1UEAxMZQ2VydHVtIFRydXN0ZWQgTmV0d29yayBDQQIRAP5\
                            n5PFaJOPGDVR8oCDCdnAwDQYJYIZIAWUDBAIBBQCgggE5MBoGCSqGSIb\
                            3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMTkwNzE\
                            wMjExMTEzWjAvBgkqhkiG9w0BCQQxIgQgRUDLNToh6+tj/k9zGTmD9ve\
                            e2jC8xkZSh1JdC9GjSaIwgcsGCyqGSIb3DQEJEAIMMYG7MIG4MIG1MIG\
                            yBBRPjUxIBklCau+LhtTV/Hky5xQthTCBmTCBg6SBgDB+MQswCQYDVQQ\
                            GEwJQTDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dpZXMgUy5BLjE\
                            nMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSI\
                            wIAYDVQQDExlDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBAhEA/mfk8Vo\
                            k48YNVHygIMJ2cDANBgkqhkiG9w0BAQEFAASCAQAw3VRwjxK1DE3RC8Q\
                            XDav3WclEZVgzVzYzEYSOnLHTOKIDu+NQjnUf6MhaQQ/gPMRsuUl5Ajh\
                            dJjofTlFxbhfaGJNGoRPJUZSjS3SFXcc3jHmn5NV+/XipT3aU/HVd+IA\
                            1BUlhcCtCqMShY+V6e1ZZ9Or4LZyk3ple9Rzom0BcD2OnLOpEzQrubDF\
                            r6xKAE/mQftAnuQ6wsqPBXI/yF6B1bYD68yANodj8xqmUs33NvNMb+2o\
                            NIgLqT4e1FdMmrOT1ASPv/Rj1DTyxdA0JDpAEFYHm5xWK36r85xTcbK4\
                            Hi7T3O9UvPCrihpDJepcoFNBibFlYOFfllYW68X1frWSjAAAA"
                            .as_bytes()
                            .to_vec(),
                        )),
                    }
                ],
                nameservers: vec![],
                additional: vec![],
                error_flags: ErrorFlags::none(),
            }
        )))
    ),
    case::parse_soa_response_with_opt_ar(
        &[
            0x82, 0x95, // Transaction ID: 0x8295
            0x81, 0x83, // Flags: response, recursion desired, recursion available, NAMEERROR
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x01, // NSCOUNT: 1
            0x00, 0x01, // ARCOUNT: 1
            0x03, 0x64, 0x6e, 0x65, 0x04, 0x6f, 0x69, 0x73, 0x66, 0x03, 0x6e, 0x65, 0x74, 0x00,
            // question: dne.oisf.net
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0xc0, 0x10, // Auth NS: dne.oisf.net
            0x00, 0x06, // RTYPE: SOA
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x03, 0x83, // TTL: 899
            0x00, 0x45, // Data length: 69
            0x06, 0x6e, 0x73, 0x2d, 0x31, 0x31, 0x30, 0x09, 0x61, 0x77, 0x73, 0x64, 0x6e, 0x73,
            0x2d, 0x31, 0x33, 0x03, 0x63, 0x6f, 0x6d, 0x00, // ns-110.awsdns-13.com
            0x11, 0x61, 0x77, 0x73, 0x64, 0x6e, 0x73, 0x2d, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61,
            0x73, 0x74, 0x65, 0x72, 0x06, 0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0xc0, 0x3b,
            // Mailbox: awsdns-hostmaster.amazon.com
            0x00, 0x00, 0x00, 0x01, // Serial number: 1
            0x00, 0x00, 0x1c, 0x20, // Refresh interval: 7200
            0x00, 0x00, 0x03, 0x84, // Retry interval: 900
            0x00, 0x12, 0x75, 0x00, // Expire limit: 1209600
            0x00, 0x01, 0x51, 0x80, // Minimum TTL: 86400
            0x00, // Additional answer: <Root>
            0x00, 0x29, // RType: OPT
            0x02, 0x00, // UDP payload size: 512
            0x00, 0x00, // Higher bits in extended RCode: 0x00
            0x00, // EDNS0 version: 0
            0x00, 0x00, // Z: 0
            0x00, // Data length: 0
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
                transaction_id: 0x8295,
                flags: 0b1000_0001_1000_0011,
                query_response: QueryResponse::Response,
                opcode: OpCode::QUERY,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                zflag: false,
                authenticated_data: false,
                check_disabled: false,
                rcode: ResponseCode::NAMEERROR,
                qdcount: 1,
                ancount: 0,
                nscount: 1,
                arcount: 1,
            },
            queries: vec![
                Question {
                    name: b"dne.oisf.net".to_vec(),
                    record_type: RecordType::A,
                    record_type_raw: 1,
                    record_class: RecordClass::IN,
                    record_class_raw: 1,
                }
            ],
            answers: vec![],
            nameservers: vec![
                Answer {
                    name: b"oisf.net".to_vec(),
                    rtype: RecordType::SOA,
                    rtype_raw: 6,
                    rclass: RecordClass::IN,
                    rclass_raw: 1,
                    ttl: 899,
                    data: (RDataType::SOA(RDataSoa {
                        mname: b"ns-110.awsdns-13.com".to_vec(),
                        rname: b"awsdns-hostmaster.amazon.com".to_vec(),
                        serial: 1,
                        refresh: 7200,
                        retry: 900,
                        expire: 1_209_600,
                        minimum: 86400,
                    })),
                }
            ],
            additional: vec![
                Answer {
                    name: vec![0x00],
                    rtype: RecordType::OPT,
                    rtype_raw: 41,
                    rclass: RecordClass::NONE,
                    rclass_raw: 254,
                    ttl: 0,
                    data: (RDataType::OPT(RDataOPT {
                        udp_payload_size: 512,
                        extended_rcode: 0x00,
                        version: 0,
                        flags: 0,
                        data: vec![],
                    })),
                }
            ],
            error_flags: ErrorFlags::none(),
            }
        )))
    ),
    case::multiple_opt_responses(
        &[
            0x82, 0x95, // Transaction ID: 0x8295
            0x81, 0x83, // Flags: response, recursion desired, recursion available, NAMEERROR
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x02, // ARCOUNT: 2
            0x03, 0x64, 0x6e, 0x65, 0x04, 0x6f, 0x69, 0x73, 0x66, 0x03, 0x6e, 0x65, 0x74, 0x00,
            // question: dne.oisf.net
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, // Additional answer: <Root>
            0x00, 0x29, // RType: OPT
            0x02, 0x00, // UDP payload size: 512
            0x00, 0x00, // Higher bits in extended RCode: 0x00
            0x00, // EDNS0 version: 0
            0x00, 0x00, // Z: 0
            0x00, // Data length: 0
            0x00, // Additional answer: <Root>
            0x00, 0x29, // RType: OPT
            0x02, 0x00, // UDP payload size: 512
            0x00, 0x00, // Higher bits in extended RCode: 0x00
            0x00, // EDNS0 version: 0
            0x00, 0x00, // Z: 0
            0x00, // Data length: 0
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
                    transaction_id: 0x8295,
                    flags: 0b1000_0001_1000_0011,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::QUERY,
                    authoritative: false,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: true,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NAMEERROR,
                    qdcount: 1,
                    ancount: 0,
                    nscount: 0,
                    arcount: 2,
                },
                queries: vec![
                    Question {
                        name: vec![100, 110, 101, 46, 111, 105, 115, 102, 46, 110, 101, 116],
                        record_type: RecordType::A,
                        record_type_raw: 1,
                        record_class: RecordClass::IN,
                        record_class_raw: 1,
                    }
                ],
                answers: vec![],
                nameservers: vec![],
                additional: vec![
                    Answer {
                        name: vec![0x00],
                        rtype: RecordType::OPT,
                        rtype_raw: 41,
                        rclass: RecordClass::NONE,
                        rclass_raw: 254,
                        ttl: 0,
                        data: (RDataType::OPT(RDataOPT {
                            udp_payload_size: 512,
                            extended_rcode: 0x00,
                            version: 0,
                            flags: 0,
                            data: vec![],
                        })),
                    },
                    Answer {
                        name: vec![0x00],
                        rtype: RecordType::OPT,
                        rtype_raw: 41,
                        rclass: RecordClass::NONE,
                        rclass_raw: 254,
                        ttl: 0,
                        data: (RDataType::OPT(RDataOPT {
                            udp_payload_size: 512,
                            extended_rcode: 0x00,
                            version: 0,
                            flags: 0,
                            data: vec![],
                        })),
                    },
                ],
                error_flags: ErrorFlags::ExtraOptRr.into(),
            }
        )))
    ),
    case::parse_opt_ar_not_enough_data(
        &[
            0x82, 0x95, // Transaction ID: 0x8295
            0x81, 0x83, // Flags: response, recursion desired, recursion available, NAMEERROR
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x01, // NSCOUNT: 1
            0x00, 0x01, // ARCOUNT: 1
            0x03, 0x64, 0x6e, 0x65, 0x04, 0x6f, 0x69, 0x73, 0x66, 0x03, 0x6e, 0x65, 0x74, 0x00,
            // question: dne.oisf.net
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0xc0, 0x10, // Auth NS: dne.oisf.net
            0x00, 0x06, // RTYPE: SOA
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x03, 0x83, // TTL: 899
            0x00, 0x45, // Data length: 69
            0x06, 0x6e, 0x73, 0x2d, 0x31, 0x31, 0x30, 0x09, 0x61, 0x77, 0x73, 0x64, 0x6e, 0x73,
            0x2d, 0x31, 0x33, 0x03, 0x63, 0x6f, 0x6d, 0x00, // ns-110.awsdns-13.com
            0x11, 0x61, 0x77, 0x73, 0x64, 0x6e, 0x73, 0x2d, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61,
            0x73, 0x74, 0x65, 0x72, 0x06, 0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0xc0, 0x3b,
            // Mailbox: awsdns-hostmaster.amazon.com
            0x00, 0x00, 0x00, 0x01, // Serial number: 1
            0x00, 0x00, 0x1c, 0x20, // Refresh interval: 7200
            0x00, 0x00, 0x03, 0x84, // Retry interval: 900
            0x00, 0x12, 0x75, 0x00, // Expire limit: 1209600
            0x00, 0x01, 0x51, 0x80, // Minimum TTL: 86400
            0x00, // Additional answer: <Root>
            0x00, 0x29, // RType: OPT
            0x02, 0x00, // UDP payload size: 512
            0x00, // Higher bits in extended RCode: 0x00
            0x00, // EDNS0 version: 0
            0x00, 0x00, // Z: 0
            0x00, 0x10, // Data length: 10
        ],
        Err(Error::incomplete_needed(2))
    ),
    case::parse_srv_response(
        &[
            0xc4, 0xdb, // Transaction ID: 0xc4db
            0x85, 0x80, // Flags: response, authoritative, recursion desired, recursion not available
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x09, 0x5f, 0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73, 0x04, 0x5f, 0x74, 0x63,
            0x70, 0x05, 0x53, 0x41, 0x4d, 0x42, 0x41, 0x07, 0x45, 0x58, 0x41, 0x4d, 0x50, 0x4c,
            0x45, 0x03, 0x43, 0x4f, 0x4d, 0x00, // question: _kerberos._tcp.SAMBA.EXAMPLE.COM
            0x00, 0x21, // RType: SRV
            0x00, 0x01, // RClass: IN
            0xc0, 0x0c, // answer: _kerberos._tcp.SAMBA.EXAMPLE.COM
            0x00, 0x21, // RType: SRV
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x03, 0x84, // TTL: 900
            0x00, 0x21, // Data length: 33
            0x00, 0x00, // priority: 0
            0x00, 0x64, // weight: 100
            0x00, 0x58, // port: 88
            0x07, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x64, 0x63, 0x05, 0x73, 0x61, 0x6d, 0x62, 0x61,
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
            0x00, // target: localdc.samba.example.com
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
                    transaction_id: 0xc4db,
                    flags: 0b1000_0101_1000_0000,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::QUERY,
                    authoritative: true,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: true,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NOERROR,
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0
                },
                queries: vec![
                    Question {
                        name: b"_kerberos._tcp.SAMBA.EXAMPLE.COM".to_vec(),
                        record_type: RecordType::SRV,
                        record_type_raw: 33,
                        record_class: RecordClass::IN,
                        record_class_raw: 1,
                    }
                ],
                answers: vec![
                    Answer {
                        name: b"_kerberos._tcp.SAMBA.EXAMPLE.COM".to_vec(),
                        rtype: RecordType::SRV,
                        rtype_raw: 33,
                        rclass: RecordClass::IN,
                        rclass_raw: 1,
                        ttl: 900,
                        data: RDataType::SRV(RDataSRV {
                            priority: 0,
                            weight: 100,
                            port: 88,
                            target: b"localdc.samba.example.com".to_vec()
                        })
                    }
                ],
                nameservers: vec![],
                additional: vec![],
                error_flags: ErrorFlags::none()
            }
        )))
    ),
    case::parse_sshfp_response(
        &[
            0x70, 0x31, // transaction id: 0x7031
            0x81,
            0xa0, // Flags: response, recursion desired, recursion available, authenticated
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x08, // ANCOUNT: 8
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x01, // ARCOUNT: 1
            0x08, 0x6d, 0x61, 0x6e, 0x79, 0x2d, 0x72, 0x72, 0x73, 0x08, 0x77, 0x65, 0x62, 0x65,
            0x72, 0x64, 0x6e, 0x73, 0x02, 0x64, 0x65, 0x00, // question: many-rrs.weberdns.de
            0x00, 0x2c, // RType: SSHFP
            0x00, 0x01, // RClass: IN
            0xc0, 0x0c, // answer: many-rrs.weberdns.de
            0x00, 0x2c, // RType: SSHFP
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x22, // data length: 34
            0x03, // algorithm: ECDSA
            0x02, // fingerprint type: SHA256
            0xf2, 0xb4, 0xee, 0x8f, 0x42, 0x0f, 0x05, 0x56, 0x2b, 0x23, 0x49, 0x7d, 0x41, 0x0e,
            0xea, 0x8d, 0xfa, 0xe6, 0x01, 0x7d, 0xba, 0x82, 0x51, 0xc2, 0x63, 0x36, 0x8a, 0x57,
            0x94, 0xb5, 0xd7, 0x43,
            // fingerprint: f2b4ee8f420f05562b23497d410eea8dfae6017dba8251c263368a5794b5d743
            0xc0, 0x0c, // answer: many-rrs.weberdns.de
            0x00, 0x2c, // RType: SSHFP
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x16, // data length: 22
            0x04, // algorithm: Ed25519
            0x01, // fingerprint type: SHA1
            0xe9, 0xd7, 0x62, 0xca, 0x6b, 0x63, 0x93, 0x1a, 0x92, 0xde, 0x1c, 0x69, 0x7d, 0xe3,
            0x25, 0x76, 0xb8, 0xf6, 0x88, 0xf7,
            // fingerprint: e9d762ca6b63931a92de1c697de32576b8f688f7
            0xc0, 0x0c, // answer: many-rrs.weberdns.de
            0x00, 0x2c, // RType: SSHFP
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x22, // data length: 34
            0x02, // algorithm: DSA
            0x02, // fingerprint type: SHA256
            0x23, 0xfb, 0x15, 0x47, 0x76, 0x9a, 0x83, 0x1b, 0x44, 0x21, 0x30, 0x0e, 0x69, 0xbd,
            0xff, 0xcd, 0xd1, 0x65, 0x00, 0x10, 0x0a, 0x3c, 0xd5, 0xb9, 0xce, 0xd7, 0xc6, 0x89,
            0xde, 0xbb, 0x09, 0xe7,
            // fingerprint: 23fb1547769a831b4421300e69bdffcdd16500100a3cd5b9ced7c689debb09e7
            0xc0, 0x0c, // answer: many-rrs.weberdns.de
            0x00, 0x2c, // RType: SSHFP
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x22, // data length: 34
            0x01, // algorithm: RSA
            0x02, // fingerprint type: SHA256
            0x49, 0x00, 0xa9, 0x38, 0xd3, 0xd6, 0x67, 0x80, 0x28, 0x2b, 0xd1, 0x1e, 0xd0, 0xb1,
            0xad, 0xd1, 0x85, 0xb8, 0x40, 0xa5, 0xe5, 0x35, 0x93, 0xc7, 0xe3, 0xb6, 0x1f, 0x05,
            0xb6, 0x38, 0x09, 0x57,
            // fingerprint: 4900a938d3d66780282bd11ed0b1add185b840a5e53593c7e3b61f05b6380957
            0xc0, 0x0c, // answer: many-rrs.weberdns.de
            0x00, 0x2c, // RType: SSHFP
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x16, // data length: 22
            0x01, // algorithm: RSA
            0x01, // fingerprint type: SHA1
            0x3e, 0xef, 0xea, 0x71, 0xca, 0x65, 0xfb, 0x5d, 0x8f, 0x45, 0xf4, 0x33, 0x0b, 0x72,
            0x68, 0xb4, 0xa4, 0x1d, 0x14, 0xa5,
            // fingerprint: 3eefea71ca65fb5d8f45f4330b7268b4a41d14a5
            0xc0, 0x0c, // answer: many-rrs.weberdns.de
            0x00, 0x2c, // RType: SSHFP
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x16, // data length: 22
            0x03, // algorithm: ECDSA
            0x01, // fingerprint type: SHA1
            0x1f, 0x2d, 0x63, 0x72, 0x57, 0x10, 0xd1, 0x5c, 0x14, 0xfd, 0x88, 0xab, 0xf4, 0xec,
            0x9c, 0xab, 0x05, 0x54, 0xc6, 0x33,
            // fingerprint: 1f2d63725710d15c14fd88abf4ec9cab0554c633
            0xc0, 0x0c, // answer: many-rrs.weberdns.de
            0x00, 0x2c, // RType: SSHFP
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x22, // data length: 34
            0x04, // algorithm: Ed25519
            0x02, // fingerprint type: SHA256
            0x94, 0x92, 0x2e, 0xc5, 0xb5, 0xdb, 0x59, 0xe4, 0x81, 0xad, 0x9d, 0x92, 0xaf, 0x3d,
            0x8a, 0x51, 0x0b, 0x1a, 0x64, 0x6c, 0x14, 0xa4, 0x96, 0x32, 0x43, 0x9b, 0x58, 0x7b,
            0x16, 0xf8, 0xf7, 0xbe,
            // fingerprint: 94922ec5b5db59e481ad9d92af3d8a510b1a646c14a49632439b587b16f8f7be
            0xc0, 0x0c, // answer: many-rrs.weberdns.de
            0x00, 0x2c, // RType: SSHFP
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x16, // data length: 22
            0x02, // algorithm: DSA
            0x01, // fingerprint type: SHA1
            0x5d, 0xed, 0xb2, 0x7f, 0x44, 0x8e, 0x1f, 0x5c, 0xbc, 0x67, 0x73, 0xbb, 0xc6, 0xc5,
            0x0e, 0x51, 0xdf, 0xc1, 0xe1, 0x8d,
            // fingerprint: 5dedb27f448e1f5cbc6773bbc6c50e51dfc1e18d
            0x00, // Additional answer: <Root>
            0x00, 0x29, // RType: OPT
            0x10, 0x00, // UDP payload size: 4096
            0x00, // Higher bits in extended RCode: 0x00
            0x00, // EDNS0 version: 0
            0x00, 0x00, // Z: 0
            0x00, 0x00, // data length: 0
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
                transaction_id: 0x7031,
                flags: 0b1000_0001_1010_0000,
                query_response: QueryResponse::Response,
                opcode: OpCode::QUERY,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                zflag: false,
                authenticated_data: true,
                check_disabled: false,
                rcode: ResponseCode::NOERROR,
                qdcount: 1,
                ancount: 8,
                nscount: 0,
                arcount: 1
            },
            queries: vec![
                Question {
                    name: b"many-rrs.weberdns.de".to_vec(),
                    record_type: RecordType::SSHFP,
                    record_type_raw: 44,
                    record_class: RecordClass::IN,
                    record_class_raw: 1,
                }
            ],
            answers: vec![
                Answer {
                    name: b"many-rrs.weberdns.de".to_vec(),
                    rtype: RecordType::SSHFP,
                    rtype_raw: 44,
                    rclass: RecordClass::IN,
                    rclass_raw: 1,
                    ttl: 3600,
                    data: (RDataType::SSHFP(RDataSSHFP {
                        algorithm: SshfpAlgorithm::ECDSA,
                        fingerprint_type: SshfpFingerprint::SHA256,
                        fingerprint: vec![
                        0xf2, 0xb4, 0xee, 0x8f, 0x42, 0x0f, 0x05, 0x56, 0x2b, 0x23, 0x49,
                        0x7d, 0x41, 0x0e, 0xea, 0x8d, 0xfa, 0xe6, 0x01, 0x7d, 0xba, 0x82,
                        0x51, 0xc2, 0x63, 0x36, 0x8a, 0x57, 0x94, 0xb5, 0xd7, 0x43,
                        ]
                    }))
                },
                Answer {
                    name: b"many-rrs.weberdns.de".to_vec(),
                    rtype: RecordType::SSHFP,
                    rtype_raw: 44,
                    rclass: RecordClass::IN,
                    rclass_raw: 1,
                    ttl: 3600,
                    data: (RDataType::SSHFP(RDataSSHFP {
                        algorithm: SshfpAlgorithm::Ed25519,
                        fingerprint_type: SshfpFingerprint::SHA1,
                        fingerprint: vec![
                        0xe9, 0xd7, 0x62, 0xca, 0x6b, 0x63, 0x93, 0x1a, 0x92, 0xde, 0x1c,
                        0x69, 0x7d, 0xe3, 0x25, 0x76, 0xb8, 0xf6, 0x88, 0xf7,
                        ]
                    }))
                },
                Answer {
                    name: b"many-rrs.weberdns.de".to_vec(),
                    rtype: RecordType::SSHFP,
                    rtype_raw: 44,
                    rclass: RecordClass::IN,
                    rclass_raw: 1,
                    ttl: 3600,
                    data: (RDataType::SSHFP(RDataSSHFP {
                        algorithm: SshfpAlgorithm::DSA,
                        fingerprint_type: SshfpFingerprint::SHA256,
                        fingerprint: vec![
                        0x23, 0xfb, 0x15, 0x47, 0x76, 0x9a, 0x83, 0x1b, 0x44, 0x21, 0x30,
                        0x0e, 0x69, 0xbd, 0xff, 0xcd, 0xd1, 0x65, 0x00, 0x10, 0x0a, 0x3c,
                        0xd5, 0xb9, 0xce, 0xd7, 0xc6, 0x89, 0xde, 0xbb, 0x09, 0xe7,
                        ]
                    }))
                },
                Answer {
                    name: b"many-rrs.weberdns.de".to_vec(),
                    rtype: RecordType::SSHFP,
                    rtype_raw: 44,
                    rclass: RecordClass::IN,
                    rclass_raw: 1,
                    ttl: 3600,
                    data: (RDataType::SSHFP(RDataSSHFP {
                        algorithm: SshfpAlgorithm::RSA,
                        fingerprint_type: SshfpFingerprint::SHA256,
                        fingerprint: vec![
                        0x49, 0x00, 0xa9, 0x38, 0xd3, 0xd6, 0x67, 0x80, 0x28, 0x2b, 0xd1,
                        0x1e, 0xd0, 0xb1, 0xad, 0xd1, 0x85, 0xb8, 0x40, 0xa5, 0xe5, 0x35,
                        0x93, 0xc7, 0xe3, 0xb6, 0x1f, 0x05, 0xb6, 0x38, 0x09, 0x57,
                        ]
                    }))
                },
                Answer {
                    name: b"many-rrs.weberdns.de".to_vec(),
                    rtype: RecordType::SSHFP,
                    rtype_raw: 44,
                    rclass: RecordClass::IN,
                    rclass_raw: 1,
                        ttl: 3600,
                        data: (RDataType::SSHFP(RDataSSHFP {
                        algorithm: SshfpAlgorithm::RSA,
                        fingerprint_type: SshfpFingerprint::SHA1,
                        fingerprint: vec![
                        0x3e, 0xef, 0xea, 0x71, 0xca, 0x65, 0xfb, 0x5d, 0x8f, 0x45, 0xf4,
                        0x33, 0x0b, 0x72, 0x68, 0xb4, 0xa4, 0x1d, 0x14, 0xa5,
                        ]
                    }))
                },
                Answer {
                    name: b"many-rrs.weberdns.de".to_vec(),
                    rtype: RecordType::SSHFP,
                    rtype_raw: 44,
                    rclass: RecordClass::IN,
                    rclass_raw: 1,
                    ttl: 3600,
                    data: (RDataType::SSHFP(RDataSSHFP {
                        algorithm: SshfpAlgorithm::ECDSA,
                        fingerprint_type: SshfpFingerprint::SHA1,
                        fingerprint: vec![
                        0x1f, 0x2d, 0x63, 0x72, 0x57, 0x10, 0xd1, 0x5c, 0x14, 0xfd, 0x88,
                        0xab, 0xf4, 0xec, 0x9c, 0xab, 0x05, 0x54, 0xc6, 0x33,
                        ]
                    }))
                },
                Answer {
                    name: b"many-rrs.weberdns.de".to_vec(),
                    rtype: RecordType::SSHFP,
                    rtype_raw: 44,
                    rclass: RecordClass::IN,
                    rclass_raw: 1,
                    ttl: 3600,
                    data: (RDataType::SSHFP(RDataSSHFP {
                        algorithm: SshfpAlgorithm::Ed25519,
                        fingerprint_type: SshfpFingerprint::SHA256,
                        fingerprint: vec![
                        0x94, 0x92, 0x2e, 0xc5, 0xb5, 0xdb, 0x59, 0xe4, 0x81, 0xad, 0x9d,
                        0x92, 0xaf, 0x3d, 0x8a, 0x51, 0x0b, 0x1a, 0x64, 0x6c, 0x14, 0xa4,
                        0x96, 0x32, 0x43, 0x9b, 0x58, 0x7b, 0x16, 0xf8, 0xf7, 0xbe,
                        ]
                    }))
                },
                Answer {
                    name: b"many-rrs.weberdns.de".to_vec(),
                    rtype: RecordType::SSHFP,
                    rtype_raw: 44,
                    rclass: RecordClass::IN,
                    rclass_raw: 1,
                    ttl: 3600,
                    data: (RDataType::SSHFP(RDataSSHFP {
                        algorithm: SshfpAlgorithm::DSA,
                        fingerprint_type: SshfpFingerprint::SHA1,
                        fingerprint: vec![
                        0x5d, 0xed, 0xb2, 0x7f, 0x44, 0x8e, 0x1f, 0x5c, 0xbc, 0x67, 0x73,
                        0xbb, 0xc6, 0xc5, 0x0e, 0x51, 0xdf, 0xc1, 0xe1, 0x8d,
                        ]
                    }))
                },
            ],
            nameservers: vec![],
            additional: vec![Answer {
            name: vec![0],
            rtype: RecordType::OPT,
            rtype_raw: 41,
            rclass: RecordClass::NONE,
            rclass_raw: 254,
            ttl: 0,
            data: RDataType::OPT(RDataOPT {
            udp_payload_size: 4096,
            extended_rcode: 0,
            version: 0,
            flags: 0,
            data: vec![]
            })
            }],
            error_flags: ErrorFlags::none()
            }
        )))
    ),
    case::parse_tkey_tsig_response(
    &[
        0x02, 0x34, // transaction id: 0x0234
        0x80, 0x00, // flags: Standard response, no error
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x01, // ARCOUNT: 1
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x01, // ARCOUNT: 1
        0x0a, 0x33, 0x32, 0x35, 0x39, 0x33, 0x36, 0x35, 0x39, 0x35, 0x34, 0x13, 0x73, 0x69,
        0x67, 0x2d, 0x77, 0x69, 0x6e, 0x2d, 0x73, 0x74, 0x37, 0x62, 0x6f, 0x30, 0x30, 0x33,
        0x73, 0x70, 0x6f, 0x08, 0x68, 0x6f, 0x6d, 0x65, 0x74, 0x65, 0x73, 0x74, 0x03, 0x6c,
        0x61, 0x6e, 0x00, // question: 3259365954.sig-win-st7bo003spo.hometest.lan
        0x00, 0xf9, // RType: TKEY
        0x00, 0xff, // RClass: ANY
        0x0a, 0x33, 0x32, 0x35, 0x39, 0x33, 0x36, 0x35, 0x39, 0x35, 0x34, 0x13, 0x73, 0x69,
        0x67, 0x2d, 0x77, 0x69, 0x6e, 0x2d, 0x73, 0x74, 0x37, 0x62, 0x6f, 0x30, 0x30, 0x33,
        0x73, 0x70, 0x6f, 0x08, 0x68, 0x6f, 0x6d, 0x65, 0x74, 0x65, 0x73, 0x74, 0x03, 0x6c,
        0x61, 0x6e, 0x00, // answer: 3259365954.sig-win-st7bo003spo.hometest.lan
        0x00, 0xf9, // RType: TKEY
        0x00, 0xff, // RClass: ANY
        0x00, 0x00, 0x00, 0x00, // TTL: 0
        0x00, 0xd4, // data length: 212
        0x08, 0x67, 0x73, 0x73, 0x2d, 0x74, 0x73, 0x69, 0x67,
        0x00, // algorithm name: gss-tsig
        0x50, 0xf8, 0xcf, 0xbb,
        // signature inception: Jan 17, 2013 23:29:47.000000000 Eastern Standard Time
        0x50, 0xfa, 0x21, 0x3b,
        // signature expiration: Jan 18, 2013 23:29:47.000000000 Eastern Standard Time
        0x00, 0x03, // mode: GSSAPI
        0x00, 0x00, // error: no error
        0x00, 0xba, // key size: 186
        0xa1, 0x81, 0xb7, 0x30, 0x81, 0xb4, 0xa0, 0x03, 0x0a, 0x01, 0x00, 0xa1, 0x0b, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0xa2, 0x81, 0x9f, 0x04,
        0x81, 0x9c, 0x60, 0x81, 0x99, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01,
        0x02, 0x02, 0x02, 0x00, 0x6f, 0x81, 0x89, 0x30, 0x81, 0x86, 0xa0, 0x03, 0x02, 0x01,
        0x05, 0xa1, 0x03, 0x02, 0x01, 0x0f, 0xa2, 0x7a, 0x30, 0x78, 0xa0, 0x03, 0x02, 0x01,
        0x12, 0xa2, 0x71, 0x04, 0x6f, 0x32, 0x94, 0x40, 0xf8, 0xae, 0xaa, 0xbd, 0xa2, 0x9e,
        0x7e, 0x78, 0x1d, 0x0f, 0xf0, 0x9b, 0xae, 0x14, 0x5c, 0x99, 0xc1, 0xdc, 0xb6, 0xc7,
        0xa0, 0xbd, 0x7a, 0x83, 0xed, 0x18, 0x0b, 0xf9, 0xea, 0xa0, 0x29, 0x1f, 0x0e, 0x82,
        0xd8, 0x2f, 0x1d, 0x59, 0xb9, 0xda, 0x97, 0x41, 0xf2, 0x7b, 0xab, 0xa2, 0xdb, 0x38,
        0xe9, 0xcd, 0xfe, 0x27, 0xb3, 0xbf, 0x13, 0x0a, 0xeb, 0xde, 0xa7, 0x7e, 0x55, 0x1a,
        0x6c, 0xff, 0x2d, 0x64, 0xfb, 0xfc, 0x56, 0x52, 0xb5, 0xc8, 0x28, 0x07, 0x17, 0x6c,
        0xe7, 0x57, 0xe5, 0xf5, 0xaa, 0xd5, 0x84, 0x18, 0x80, 0x21, 0xa1, 0xd9, 0xdd, 0x03,
        0x82, 0xf1, 0xcf, 0x1b, 0xe6, 0x17, 0x97, 0xee, 0x2b, 0xdd, 0x27, 0x80, 0xea, 0x42,
        0xde, 0xc8, 0x57, 0x8a,
        // key data: a181b73081b4a0030a0100a10b06092a864886f712010202a2819f04819c608199060
        // 92a864886f71201020202006f8189308186a003020105a10302010fa27a3078a003020112a27104
        // 6f329440f8aeaabda29e7e781d0ff09bae145c99c1dcb6c7a0bd7a83ed180bf9eaa0291f0e82d82
        // f1d59b9da9741f27baba2db38e9cdfe27b3bf130aebdea77e551a6cff2d64fbfc5652b5c8280717
        // 6ce757e5f5aad584188021a1d9dd0382f1cf1be61797ee2bdd2780ea42dec8578a
        0x00, 0x00, // other size: 0
        0x0a, 0x33, 0x32, 0x35, 0x39, 0x33, 0x36, 0x35, 0x39, 0x35, 0x34, 0x13, 0x73, 0x69,
        0x67, 0x2d, 0x77, 0x69, 0x6e, 0x2d, 0x73, 0x74, 0x37, 0x62, 0x6f, 0x30, 0x30, 0x33,
        0x73, 0x70, 0x6f, 0x08, 0x68, 0x6f, 0x6d, 0x65, 0x74, 0x65, 0x73, 0x74, 0x03, 0x6c,
        0x61, 0x6e, 0x00, // answer: 3259365954.sig-win-st7bo003spo.hometest.lan
        0x00, 0xfa, // RType: TSIG
        0x00, 0xff, // RClass: ANY
        0x00, 0x00, 0x00, 0x00, // TTL: 0
        0x00, 0x36, // data length: 54
        0x08, 0x67, 0x73, 0x73, 0x2d, 0x74, 0x73, 0x69, 0x67,
        0x00, // algorithm type: gss-tsig
        0x00, 0x00, 0x50, 0xf8, 0xcf, 0xbb,
        // time signed: Jan 17, 2013 23:29:47.000000000 Eastern Standard Time
        0x8c, 0xa0, // fudge: 36000
        0x00, 0x1c, // MAC size: 28
        0x04, 0x04, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x73, 0x28,
        0x5d, 0x0a, 0x2d, 0xf4, 0xa3, 0x34, 0x2f, 0xcf, 0x01, 0x6f, 0x3c, 0x9f, 0x76, 0x82,
        // MAC: 040405ffffffffff0000000073285d0a2df4a3342fcf016f3c9f7682
        0x02, 0x34, // original id: 564
        0x00, 0x00, // error: no error
        0x00, 0x00, // other length: 0
    ],
    Ok((
    0,
    Some(
        Message {
        header: Header {
            transaction_id: 0x0234,
            flags: 0b1000_0000_0000_0000,
            query_response: QueryResponse::Response,
            opcode: OpCode::QUERY,
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            zflag: false,
            authenticated_data: false,
            check_disabled: false,
            rcode: ResponseCode::NOERROR,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 1
        },
        queries: vec![
            Question {
                name: "3259365954.sig-win-st7bo003spo.hometest.lan"
                .as_bytes()
                .to_vec(),
                record_type: RecordType::TKEY,
                record_type_raw: 249,
                record_class: RecordClass::ANY,
                record_class_raw: 255,
            }
        ],
        answers: vec![
            Answer {
                name: "3259365954.sig-win-st7bo003spo.hometest.lan"
                .as_bytes()
                .to_vec(),
                rtype: RecordType::TKEY,
                rtype_raw: 249,
                rclass: RecordClass::ANY,
                rclass_raw: 255,
                ttl: 0,
                data: RDataType::TKEY(RDataTKEY {
                    algorithm: b"gss-tsig".to_vec(),
                    inception: 1_358_483_387,
                    expiration: 1_358_569_787,
                    mode: TkeyMode::GssApiNegotiation,
                    error: TSigResponseCode::NOERROR,
                    key_data: vec![
                    0xa1, 0x81, 0xb7, 0x30, 0x81, 0xb4, 0xa0, 0x03, 0x0a, 0x01, 0x00, 0xa1,
                    0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
                    0xa2, 0x81, 0x9f, 0x04, 0x81, 0x9c, 0x60, 0x81, 0x99, 0x06, 0x09, 0x2a,
                    0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x02, 0x00, 0x6f, 0x81,
                    0x89, 0x30, 0x81, 0x86, 0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x03, 0x02,
                    0x01, 0x0f, 0xa2, 0x7a, 0x30, 0x78, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa2,
                    0x71, 0x04, 0x6f, 0x32, 0x94, 0x40, 0xf8, 0xae, 0xaa, 0xbd, 0xa2, 0x9e,
                    0x7e, 0x78, 0x1d, 0x0f, 0xf0, 0x9b, 0xae, 0x14, 0x5c, 0x99, 0xc1, 0xdc,
                    0xb6, 0xc7, 0xa0, 0xbd, 0x7a, 0x83, 0xed, 0x18, 0x0b, 0xf9, 0xea, 0xa0,
                    0x29, 0x1f, 0x0e, 0x82, 0xd8, 0x2f, 0x1d, 0x59, 0xb9, 0xda, 0x97, 0x41,
                    0xf2, 0x7b, 0xab, 0xa2, 0xdb, 0x38, 0xe9, 0xcd, 0xfe, 0x27, 0xb3, 0xbf,
                    0x13, 0x0a, 0xeb, 0xde, 0xa7, 0x7e, 0x55, 0x1a, 0x6c, 0xff, 0x2d, 0x64,
                    0xfb, 0xfc, 0x56, 0x52, 0xb5, 0xc8, 0x28, 0x07, 0x17, 0x6c, 0xe7, 0x57,
                    0xe5, 0xf5, 0xaa, 0xd5, 0x84, 0x18, 0x80, 0x21, 0xa1, 0xd9, 0xdd, 0x03,
                    0x82, 0xf1, 0xcf, 0x1b, 0xe6, 0x17, 0x97, 0xee, 0x2b, 0xdd, 0x27, 0x80,
                    0xea, 0x42, 0xde, 0xc8, 0x57, 0x8a,
                    ],
                    other_data: vec![]
                })
            }
        ],
        nameservers: vec![],
        additional: vec![
            Answer {
                name: "3259365954.sig-win-st7bo003spo.hometest.lan"
                .as_bytes()
                .to_vec(),
                rtype: RecordType::TSIG,
                rtype_raw: 250,
                rclass: RecordClass::ANY,
                rclass_raw: 255,
                ttl: 0,
                data: RDataType::TSIG(RDataTSIG {
                    algorithm_name: b"gss-tsig".to_vec(),
                    time_signed: 1_358_483_387,
                    fudge: 36000,
                    mac: vec![
                    0x04, 0x04, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                    0x73, 0x28, 0x5d, 0x0a, 0x2d, 0xf4, 0xa3, 0x34, 0x2f, 0xcf, 0x01, 0x6f,
                    0x3c, 0x9f, 0x76, 0x82
                    ],
                    original_id: 564,
                    error: TSigResponseCode::NOERROR,
                    other_data: vec![]
                })
            }
        ],
        error_flags: ErrorFlags::none()
        }
    )))
    ),
    case::parse_caa_response(
        &[
            0x35, 0x5e, // transaction id: 0x355e
            0x81,
            0x80, // flags: Standard response, recursion desired, recursion available, no error
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            // question: google.com
            0x01, 0x01, // RType: CAA
            0x00, 0x01, // RClass: IN
            0xc0, 0x0c, // answer: google.com
            0x01, 0x01, // RType: CAA
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x54, 0x49, // TTL: 21577
            0x00, 0x13, // data length: 19
            0x00, // CAA flags: 0x00
            0x05, // tag length: 5
            0x69, 0x73, 0x73, 0x75, 0x65, // tag: issue
            0x73, 0x79, 0x6d, 0x61, 0x6e, 0x74, 0x65, 0x63, 0x2e, 0x63, 0x6f,
            0x6d,
            // issue: symantec.com
        ],
        Ok((
        0,
        Some(
            Message {
                header: Header {
                    transaction_id: 0x355e,
                    flags: 0b1000_0001_1000_0000,
                    query_response: QueryResponse::Response,
                    opcode: OpCode::QUERY,
                    authoritative: false,
                    truncated: false,
                    recursion_desired: true,
                    recursion_available: true,
                    zflag: false,
                    authenticated_data: false,
                    check_disabled: false,
                    rcode: ResponseCode::NOERROR,
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0
                },
                queries: vec![Question {
                    name: b"google.com".to_vec(),
                    record_type: RecordType::CAA,
                    record_type_raw: 257,
                    record_class: RecordClass::IN,
                    record_class_raw: 1,
                }],
                answers: vec![Answer {
                    name: b"google.com".to_vec(),
                    rtype: RecordType::CAA,
                    rtype_raw: 257,
                    rclass: RecordClass::IN,
                    rclass_raw: 1,
                    ttl: 21577,
                    data: RDataType::CAA(RDataCAA {
                        flags: 0,
                        tag: b"issue".to_vec(),
                        value: b"symantec.com".to_vec()
                })
                }],
                nameservers: vec![],
                additional: vec![],
                error_flags: ErrorFlags::none()
            }
        )))
    ),
    )]
    fn dns(input: &[u8], expected: Result<(usize, Option<Message>)>) {
        let dns = Dns {};
        assert_eq!(
            dns.parse(input, Direction::Unknown)
                .map(|(rem, msg)| (rem.len(), msg)),
            expected
        );
    }
}
