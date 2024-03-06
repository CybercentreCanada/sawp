use nom::number::streaming::be_u16;

use sawp_flags::{Flag, Flags};

use crate::enums::{RecordClass, RecordType};
use crate::{custom_count, ErrorFlags, IResult, Name};

#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

/// A parsed DNS question
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_dns"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Question {
    pub name: Vec<u8>,
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub record_type: RecordType,
    pub record_type_raw: u16,
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub record_class: RecordClass,
    pub record_class_raw: u16,
}

impl Question {
    fn parse<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
    ) -> IResult<'a, (Question, Flags<ErrorFlags>)> {
        let (input, (name, mut error_flags)) = Name::parse(reference_bytes)(input)?;
        let (input, working_qtype) = be_u16(input)?;
        let qtype: RecordType = RecordType::from_raw(working_qtype);
        if qtype == RecordType::UNKNOWN {
            error_flags |= ErrorFlags::UnknownRtype;
        }

        let (input, working_qclass) = be_u16(input)?;
        let qclass: RecordClass = RecordClass::from_raw(working_qclass);
        if qclass == RecordClass::UNKNOWN {
            error_flags |= ErrorFlags::UnknownRclass;
        }

        Ok((
            input,
            (
                Question {
                    name,
                    record_class: qclass,
                    record_class_raw: working_qclass,
                    record_type: qtype,
                    record_type_raw: working_qtype,
                },
                error_flags,
            ),
        ))
    }

    pub fn parse_questions<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
        qdcnt: usize,
    ) -> IResult<'a, (Vec<Question>, Flags<ErrorFlags>)> {
        let mut error_flags = ErrorFlags::none();

        let (input, questions) = custom_count(
            |input, reference_bytes| {
                let (input, (answer, inner_error_flags)) = Question::parse(input, reference_bytes)?;
                error_flags |= inner_error_flags;
                Ok((input, answer))
            },
            qdcnt,
        )(input, reference_bytes)?;
        Ok((input, (questions, error_flags)))
    }
}
