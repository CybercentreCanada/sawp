//! Extended DNS
//! [RFC6891](https://tools.ietf.org/html/rfc6891)
//!
//! EDNS adds information to DNS messages in the form of pseudo-Resource Records
//! ("pseudo-RR"s) included in the "additional data" section of a DNS message.
//! This takes the form of an OPT RR which contains a UDP payload size the server supports,
//! an EDNS version number, flags, an extended RCode, and possibly a variable number of KVP options.
//! Most notably this allows servers to advertise that they can process UDP messages of size > 512
//! bytes (the default maximum for DNS over UDP).

use nom::bytes::streaming::take;
use nom::number::streaming::be_u16;

use num_enum::TryFromPrimitive;

use sawp_flags::{Flag, Flags};

use std::convert::TryFrom;

use crate::{custom_many0, ErrorFlags, IResult};
#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum OptionCode {
    /// Long-Lived Queries
    LLQ = 1,
    /// Update Leases
    UL = 2,
    /// Name Server Identifier
    NSID = 3,
    /// DNSSEC Algorithm Understood
    DAU = 5,
    /// DS Hash Understood
    DHU = 6,
    /// NSEC3 Hash Understood
    N3U = 7,
    /// EDNS0 option to allow Recursive Resolvers, if they are willing, to forward details about the origin network from which a query is coming when talking to other nameservers
    EDNSCLIENTSUBNET = 8,
    /// See https://tools.ietf.org/html/rfc7314
    EDNSEXPIRE = 9,
    /// See https://tools.ietf.org/html/rfc7873#section-4
    COOKIE = 10,
    /// Signals a variable idle timeout
    EDNSTCPKEEPALIVE = 11,
    /// Allows DNS clients and servers to pad requests and responses by a variable number of octets
    PADDING = 12,
    /// Allows a security-aware validating resolver to send a single query requesting a complete validation path along with the regular answer
    CHAIN = 13,
    /// Provides origin authentication using digital signatures
    EDNSKEYTAG = 14,
    /// Returning additional information about the cause of DNS errors
    EDNSERROR = 15,
    /// Draft, usage is being determined. See https://www.ietf.org/archive/id/draft-bellis-dnsop-edns-tags-01.txt
    EDNSCLIENTTAG = 16,
    /// Draft, usage is being determined. See https://www.ietf.org/archive/id/draft-bellis-dnsop-edns-tags-01.txt
    EDNSSERVERTAG = 17,
    /// A way of identifying a device via DNS in the OPT RDATA
    DEVICEID = 26946,
    UNKNOWN,
}

impl OptionCode {
    pub fn from_raw(val: u16) -> Self {
        OptionCode::try_from(val).unwrap_or(OptionCode::UNKNOWN)
    }
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_dns"))]
#[derive(Debug, PartialEq, Eq)]
pub struct EdnsOption {
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub code: OptionCode,
    pub data: Vec<u8>,
}

impl EdnsOption {
    pub fn parse(input: &[u8]) -> IResult<(EdnsOption, Flags<ErrorFlags>)> {
        let (input, (code, inner_error_flags)) = EdnsOption::parse_option_code(input)?;
        let (input, option_length) = be_u16(input)?;
        let (input, data) = take(option_length)(input)?;

        Ok((
            input,
            (
                EdnsOption {
                    code,
                    data: data.to_vec(),
                },
                inner_error_flags,
            ),
        ))
    }

    fn parse_option_code(input: &[u8]) -> IResult<(OptionCode, Flags<ErrorFlags>)> {
        let mut error_flags = ErrorFlags::none();

        let (input, raw_option_code) = be_u16(input)?;
        let code = OptionCode::from_raw(raw_option_code);
        if code == OptionCode::UNKNOWN {
            error_flags |= ErrorFlags::EdnsParseFail;
        }
        Ok((input, (code, error_flags)))
    }

    pub fn parse_options(
        input: &[u8],
        data_len: u16,
    ) -> IResult<(Vec<EdnsOption>, Flags<ErrorFlags>)> {
        let mut error_flags = ErrorFlags::none();
        if data_len < 4 {
            return Ok((input, (vec![], error_flags)));
        }

        let (input, options) = custom_many0(|input| {
            let (input, (option, inner_error_flags)) = EdnsOption::parse(input)?;
            error_flags |= inner_error_flags;
            Ok((input, option))
        })(input)?;

        Ok((input, (options, error_flags)))
    }
}
