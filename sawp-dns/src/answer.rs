use nom::bytes::streaming::take;
use nom::number::complete::be_u32;
use nom::number::streaming::be_u16;

use sawp_flags::{Flag, Flags};

use crate::enums::{RecordClass, RecordType};
use crate::rdata::RDataType;
use crate::{custom_count, ErrorFlags, IResult, Name};

#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

/// Per RFC1035/RFC4408: max RDATA len = 65535 octets. Since TXT RDATA includes a length byte before
/// each TXT string, min size per TXT is 2 bytes, leaving maximum of 65535/2 parser runs needed.
const MAX_TXT_PARSES: usize = 32767;
/// First three bytes of an OPT AR - determines whether an AR should be parsed with special "OPT logic".
const OPT_RR_START: [u8; 3] = [0, 0, 41];

/// A parsed DNS answer
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_dns"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    pub name: Vec<u8>,
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub rtype: RecordType,
    pub rtype_raw: u16,
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub rclass: RecordClass,
    pub rclass_raw: u16,
    pub ttl: u32,
    pub data: RDataType,
}

impl Answer {
    fn parse<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
    ) -> IResult<'a, (Answer, Flags<ErrorFlags>)> {
        let (input, (name, mut error_flags)) = Name::parse(reference_bytes)(input)?;

        let (input, working_rtype) = be_u16(input)?;
        let rtype = RecordType::from_raw(working_rtype);
        if rtype == RecordType::UNKNOWN {
            error_flags |= ErrorFlags::UnknownRtype;
        }

        let (input, working_rclass) = be_u16(input)?;
        let rclass = RecordClass::from_raw(working_rclass);
        if rclass == RecordClass::UNKNOWN {
            error_flags |= ErrorFlags::UnknownRclass;
        }

        let (input, ttl) = be_u32(input)?;

        let mut answer: Answer = Answer {
            name,
            rtype,
            rtype_raw: working_rtype,
            rclass,
            rclass_raw: working_rclass,
            ttl,
            data: RDataType::UNKNOWN(vec![]),
        };

        let (input, data_len) = be_u16(input)?;
        let (rem, local_data) = take(data_len)(input)?;

        // always call once
        let (mut local_data, (mut rdata, inner_error_flags)) =
            RDataType::parse(local_data, reference_bytes, rtype)?;
        error_flags |= inner_error_flags;

        // get ref to buffer we will extend first, if TXT
        if let RDataType::TXT(ref mut current_rdata) = rdata {
            for _ in 0..MAX_TXT_PARSES - 1 {
                if local_data.is_empty() {
                    break;
                }
                let (new_data, (rdata, inner_error_flags)) =
                    RDataType::parse(local_data, reference_bytes, rtype)?;
                error_flags |= inner_error_flags;
                if let RDataType::TXT(new_rdata) = rdata {
                    current_rdata.extend(new_rdata);
                    local_data = new_data;
                } else {
                    break;
                }
            }
        }
        answer.data = rdata;
        Ok((rem, (answer, error_flags)))
    }

    fn parse_additional<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
    ) -> IResult<'a, (Answer, Flags<ErrorFlags>, bool)> {
        let mut opt_rr_present = false;
        if input.len() >= 3 && input[0..3] == OPT_RR_START[0..3] {
            let (input, (data, inner_error_flags)) = RDataType::parse_rdata_opt(&input[3..])?;
            opt_rr_present = true;
            Ok((
                input,
                (
                    Answer {
                        name: vec![0], // OPT RRs must be named 0 <root>
                        rtype: RecordType::OPT,
                        rtype_raw: 41,
                        rclass: RecordClass::NONE, // OPT RRs have no class
                        rclass_raw: 254,
                        ttl: 0, // OPT RRs do not contain a TTL
                        data,
                    },
                    inner_error_flags,
                    opt_rr_present,
                ),
            ))
        } else {
            let (input, (answer, inner_error_flags)) = Answer::parse(input, reference_bytes)?;
            Ok((input, (answer, inner_error_flags, opt_rr_present)))
        }
    }

    pub fn parse_additionals<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
        acnt: usize,
    ) -> IResult<'a, (Vec<Answer>, Flags<ErrorFlags>)> {
        let mut opt_rr_present = false;
        let mut error_flags = ErrorFlags::none();
        let (input, answers) = custom_count(
            |input, reference_bytes| {
                let (input, (answer, inner_error_flags, inner_opt_rr_present)) =
                    Answer::parse_additional(input, reference_bytes)?;
                if inner_opt_rr_present {
                    if opt_rr_present {
                        error_flags |= ErrorFlags::ExtraOptRr;
                    } else {
                        opt_rr_present = true;
                    }
                }
                error_flags |= inner_error_flags;
                Ok((input, answer))
            },
            acnt,
        )(input, reference_bytes)?;

        Ok((input, (answers, error_flags)))
    }

    pub fn parse_answers<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
        acnt: usize,
    ) -> IResult<'a, (Vec<Answer>, Flags<ErrorFlags>)> {
        let mut error_flags = ErrorFlags::none();
        let (input, answers) = custom_count(
            |input, reference_bytes| {
                let (input, (answer, inner_error_flags)) = Answer::parse(input, reference_bytes)?;
                error_flags |= inner_error_flags;
                Ok((input, answer))
            },
            acnt,
        )(input, reference_bytes)?;

        Ok((input, (answers, error_flags)))
    }
}
