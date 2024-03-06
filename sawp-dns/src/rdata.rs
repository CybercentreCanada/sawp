use nom::bytes::streaming::take;
use nom::number::streaming::{be_u16, be_u32, be_u8};

use sawp_flags::{Flag, Flags};

use byteorder::{BigEndian, ByteOrder};

use crate::edns::EdnsOption;
use crate::enums::{RecordType, SshfpAlgorithm, SshfpFingerprint, TSigResponseCode, TkeyMode};

use crate::{ErrorFlags, IResult, Name};
use nom::combinator::rest;
#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_dns"))]
#[derive(Debug, PartialEq, Eq)]
pub struct RDataCAA {
    pub flags: u8,
    pub tag: Vec<u8>,
    pub value: Vec<u8>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_dns"))]
#[derive(Debug, PartialEq, Eq)]
pub struct RDataOPT {
    /// Requestor's UDP payload size
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    /// EDNS version
    pub version: u8,
    pub flags: u16, // bit [0] = DO <DNSSEC Answer OK>. bit[1..15] are reserved.
    pub data: Vec<EdnsOption>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_dns"))]
#[derive(Debug, PartialEq, Eq)]
pub struct RDataSoa {
    /// Primary NS for this zone
    pub mname: Vec<u8>,
    /// Authority's mailbox
    pub rname: Vec<u8>,
    /// Serial version number
    pub serial: u32,
    /// Refresh interval in seconds
    pub refresh: u32,
    /// Retry interval in seconds
    pub retry: u32,
    /// Upper time limit until zone is no longer authoritative in seconds
    pub expire: u32,
    /// Minimum ttl for records in this zone in seconds
    pub minimum: u32,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_dns"))]
#[derive(Debug, PartialEq, Eq)]
pub struct RDataSSHFP {
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    /// Algorithm number
    pub algorithm: SshfpAlgorithm,
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub fingerprint_type: SshfpFingerprint,
    pub fingerprint: Vec<u8>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_dns"))]
#[derive(Debug, PartialEq, Eq)]
pub struct RDataSRV {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: Vec<u8>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_dns"))]
#[derive(Debug, PartialEq, Eq)]
pub struct RDataTKEY {
    pub algorithm: Vec<u8>,
    /// Time signature incepted - seconds since epoch
    pub inception: u32,
    /// Time signature expires - seconds since epoch
    pub expiration: u32,
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub mode: TkeyMode,
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub error: TSigResponseCode,
    pub key_data: Vec<u8>,
    pub other_data: Vec<u8>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_dns"))]
#[derive(Debug, PartialEq, Eq)]
pub struct RDataTSIG {
    pub algorithm_name: Vec<u8>,
    /// Seconds since epoch
    pub time_signed: u64, // only occupies 6 bytes in RData
    /// Seconds of error permitted
    pub fudge: u16,
    pub mac: Vec<u8>,
    /// Original message ID
    pub original_id: u16,
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    /// Extended rcode covering TSIG processing
    pub error: TSigResponseCode,
    /// Empty unless error == BADTIME
    pub other_data: Vec<u8>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_dns"))]
#[derive(Debug, PartialEq, Eq)]
pub enum RDataType {
    /// Addresses
    A(Vec<u8>),
    AAAA(Vec<u8>),
    /// Domain names
    CNAME(Vec<u8>),
    PTR(Vec<u8>),
    MX(Vec<u8>),
    NS(Vec<u8>),
    /// Text
    TXT(Vec<u8>),
    NUL(Vec<u8>),
    /// Multiple field records
    CAA(RDataCAA),
    OPT(RDataOPT),
    SOA(RDataSoa),
    SRV(RDataSRV),
    SSHFP(RDataSSHFP),
    TKEY(RDataTKEY),
    TSIG(RDataTSIG),
    UNKNOWN(Vec<u8>),
}

impl RDataType {
    pub fn parse<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
        rtype: RecordType,
    ) -> IResult<'a, (RDataType, Flags<ErrorFlags>)> {
        match rtype {
            RecordType::A => RDataType::parse_rdata_a(input)
                .map(|(input, rdata)| (input, (rdata, ErrorFlags::none()))),
            RecordType::AAAA => RDataType::parse_rdata_aaaa(input)
                .map(|(input, rdata)| (input, (rdata, ErrorFlags::none()))),
            RecordType::CAA => RDataType::parse_rdata_caa(input)
                .map(|(input, rdata)| (input, (rdata, ErrorFlags::none()))),
            RecordType::CNAME => RDataType::parse_rdata_cname(input, reference_bytes),
            RecordType::MX => RDataType::parse_rdata_mx(input, reference_bytes),
            RecordType::NS => RDataType::parse_rdata_ns(input, reference_bytes),
            RecordType::NUL => RDataType::parse_rdata_null(input)
                .map(|(input, rdata)| (input, (rdata, ErrorFlags::none()))),
            RecordType::OPT => RDataType::parse_rdata_opt(input),
            RecordType::PTR => RDataType::parse_rdata_ptr(input, reference_bytes),
            RecordType::SOA => RDataType::parse_rdata_soa(input, reference_bytes),
            RecordType::SRV => RDataType::parse_rdata_srv(input, reference_bytes),
            RecordType::SSHFP => RDataType::parse_rdata_sshfp(input)
                .map(|(input, rdata)| (input, (rdata, ErrorFlags::none()))),
            RecordType::TKEY => RDataType::parse_rdata_tkey(input, reference_bytes),
            RecordType::TSIG => RDataType::parse_rdata_tsig(input, reference_bytes),
            RecordType::TXT => RDataType::parse_rdata_txt(input)
                .map(|(input, rdata)| (input, (rdata, ErrorFlags::none()))),
            _ => RDataType::parse_rdata_unknown(input)
                .map(|(input, rdata)| (input, (rdata, ErrorFlags::none()))),
        }
    }

    fn parse_rdata_a(input: &[u8]) -> IResult<RDataType> {
        let (input, data) = rest(input)?;
        Ok((input, RDataType::A(data.to_vec())))
    }

    fn parse_rdata_aaaa(input: &[u8]) -> IResult<RDataType> {
        let (input, data) = rest(input)?;
        Ok((input, RDataType::AAAA(data.to_vec())))
    }

    fn parse_rdata_caa(input: &[u8]) -> IResult<RDataType> {
        let (input, flags) = be_u8(input)?;
        let (input, tag_length) = be_u8(input)?;
        let (input, tag) = take(tag_length)(input)?;
        let (input, value) = rest(input)?;

        Ok((
            input,
            RDataType::CAA(RDataCAA {
                flags,
                tag: tag.to_vec(),
                value: value.to_vec(),
            }),
        ))
    }

    fn parse_rdata_cname<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
    ) -> IResult<'a, (RDataType, Flags<ErrorFlags>)> {
        let (input, (name, error_flags)) = Name::parse(reference_bytes)(input)?;
        Ok((input, (RDataType::CNAME(name), error_flags)))
    }

    fn parse_rdata_ns<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
    ) -> IResult<'a, (RDataType, Flags<ErrorFlags>)> {
        let (input, (name, error_flags)) = Name::parse(reference_bytes)(input)?;
        Ok((input, (RDataType::NS(name), error_flags)))
    }

    fn parse_rdata_ptr<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
    ) -> IResult<'a, (RDataType, Flags<ErrorFlags>)> {
        let (input, (name, error_flags)) = Name::parse(reference_bytes)(input)?;
        Ok((input, (RDataType::PTR(name), error_flags)))
    }

    pub fn parse_rdata_opt(input: &[u8]) -> IResult<(RDataType, Flags<ErrorFlags>)> {
        let (input, udp_payload_size) = be_u16(input)?;
        let (input, extended_rcode) = be_u8(input)?;
        let (input, version) = be_u8(input)?;
        let (input, flags) = be_u16(input)?;
        let (input, data_len) = be_u16(input)?;
        let (input, (data, options_error_flags)) = EdnsOption::parse_options(input, data_len)?;

        Ok((
            input,
            (
                RDataType::OPT(RDataOPT {
                    udp_payload_size,
                    extended_rcode,
                    version,
                    flags,
                    data,
                }),
                options_error_flags,
            ),
        ))
    }

    fn parse_rdata_soa<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
    ) -> IResult<'a, (RDataType, Flags<ErrorFlags>)> {
        let (input, (mname, mut error_flags)) = Name::parse(reference_bytes)(input)?;
        let (input, (rname, inner_error_flags)) = Name::parse(reference_bytes)(input)?;

        error_flags |= inner_error_flags;

        let (input, serial) = be_u32(input)?;
        let (input, refresh) = be_u32(input)?;
        let (input, retry) = be_u32(input)?;
        let (input, expire) = be_u32(input)?;
        let (input, minimum) = be_u32(input)?;

        Ok((
            input,
            (
                RDataType::SOA(RDataSoa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }),
                error_flags,
            ),
        ))
    }

    fn parse_rdata_tkey<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
    ) -> IResult<'a, (RDataType, Flags<ErrorFlags>)> {
        let (input, (algorithm, error_flags)) = Name::parse(reference_bytes)(input)?;
        let (input, inception) = be_u32(input)?;
        let (input, expiration) = be_u32(input)?;
        let (input, mode) = be_u16(input)?;
        let (input, error) = be_u16(input)?;
        let (input, key_size) = be_u16(input)?;
        let (input, key_data) = take(key_size)(input)?;
        let (input, other_size) = be_u16(input)?;
        let (input, other_data) = take(other_size)(input)?;

        Ok((
            input,
            (
                RDataType::TKEY(RDataTKEY {
                    algorithm,
                    inception,
                    expiration,
                    mode: TkeyMode::from_raw(mode),
                    error: TSigResponseCode::from_raw(error),
                    key_data: key_data.to_vec(),
                    other_data: other_data.to_vec(),
                }),
                error_flags,
            ),
        ))
    }

    fn parse_rdata_tsig<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
    ) -> IResult<'a, (RDataType, Flags<ErrorFlags>)> {
        let (input, (algorithm_name, error_flags)) = Name::parse(reference_bytes)(input)?;
        let (input, time_signed_raw) = take(6_usize)(input)?;
        let (input, fudge) = be_u16(input)?;
        let (input, mac_size) = be_u16(input)?;
        let (input, mac) = take(mac_size)(input)?;
        let (input, original_id) = be_u16(input)?;
        let (input, error) = be_u16(input)?;
        let (input, other_len) = be_u16(input)?;
        let (input, other_data) = take(other_len)(input)?;

        Ok((
            input,
            (
                RDataType::TSIG(RDataTSIG {
                    algorithm_name,
                    time_signed: BigEndian::read_uint(time_signed_raw, 6),
                    fudge,
                    mac: mac.to_vec(),
                    original_id,
                    error: TSigResponseCode::from_raw(error),
                    other_data: other_data.to_vec(),
                }),
                error_flags,
            ),
        ))
    }

    fn parse_rdata_mx<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
    ) -> IResult<'a, (RDataType, Flags<ErrorFlags>)> {
        // Skip the preference field
        let (input, _) = be_u16(input)?;
        let (input, (name, error_flags)) = Name::parse(reference_bytes)(input)?;
        Ok((input, (RDataType::MX(name), error_flags)))
    }

    fn parse_rdata_srv<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
    ) -> IResult<'a, (RDataType, Flags<ErrorFlags>)> {
        let (input, priority) = be_u16(input)?;
        let (input, weight) = be_u16(input)?;
        let (input, port) = be_u16(input)?;
        let (input, (target, error_flags)) = Name::parse(reference_bytes)(input)?;

        Ok((
            input,
            (
                RDataType::SRV(RDataSRV {
                    priority,
                    weight,
                    port,
                    target,
                }),
                error_flags,
            ),
        ))
    }

    fn parse_rdata_txt(input: &[u8]) -> IResult<RDataType> {
        let (input, len) = be_u8(input)?;
        let (input, txt) = take(len)(input)?;
        Ok((input, RDataType::TXT(txt.to_vec())))
    }

    fn parse_rdata_null(input: &[u8]) -> IResult<RDataType> {
        let (input, data) = rest(input)?;
        Ok((input, RDataType::NUL(data.to_vec())))
    }

    fn parse_rdata_sshfp(input: &[u8]) -> IResult<RDataType> {
        let (input, algorithm) = be_u8(input)?;
        let (input, fingerprint_type) = be_u8(input)?;
        let (input, fingerprint) = rest(input)?;

        Ok((
            input,
            RDataType::SSHFP(RDataSSHFP {
                algorithm: SshfpAlgorithm::from_raw(algorithm),
                fingerprint_type: SshfpFingerprint::from_raw(fingerprint_type),
                fingerprint: fingerprint.to_vec(),
            }),
        ))
    }

    fn parse_rdata_unknown(input: &[u8]) -> IResult<RDataType> {
        let (input, data) = rest(input)?;
        Ok((input, RDataType::UNKNOWN(data.to_vec())))
    }
}
