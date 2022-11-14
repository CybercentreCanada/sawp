use crate::ErrorFlags::DnsNameInvalidCompression;
use crate::{ErrorFlags, IResult};
use nom::error::ErrorKind;
use nom::multi::length_data;
use nom::number::streaming::{be_u16, be_u8};
use sawp::error::NomError;
use sawp_flags::{Flag, Flags};

// From RFC 1035: DNS labels cannot exceed 63 characters in length
const DNS_MAX_LABEL_LEN: usize = 63;
// Similar: DNS names cannot exceed length 255.
const DNS_MAX_DOMAIN_LEN: usize = 255;
// Since min label size is 2 bytes (length byte + minimum txt of 1), the maximum number of label parses needed to parse a domain would be 255/2
const MAX_LABEL_PARSES: usize = 128;
const MSG_COMPRESSION_FLAG: u8 = 0b1100_0000;
const MSG_COMPRESSION_OFFSET_MASK: u16 = 0b0011_1111_1111_1111;

#[derive(Debug)]
pub struct Name {}

impl Name {
    fn parse_label(input: &[u8]) -> IResult<(&[u8], Flags<ErrorFlags>)> {
        let (rem, label) = length_data::<_, _, sawp::error::NomError<&[u8]>, _>(be_u8)(input)?;

        let error_flags = if label.len() > DNS_MAX_LABEL_LEN {
            ErrorFlags::DnsLabelExceedsMaxLen.into()
        } else {
            ErrorFlags::none()
        };

        Ok((rem, (label, error_flags)))
    }

    fn name_is_compressed(len: u8) -> bool {
        len & MSG_COMPRESSION_FLAG == MSG_COMPRESSION_FLAG
    }

    fn follow_compressed_segment<'a>(
        input: &'a [u8],
        reference_bytes: &'a [u8],
    ) -> IResult<'a, &'a [u8]> {
        let (rem, referenced_name_loc) = be_u16::<_, sawp::error::NomError<&[u8]>>(input)?;
        if let Some(offset) = reference_bytes
            .get(usize::from(referenced_name_loc) & MSG_COMPRESSION_OFFSET_MASK as usize..)
        {
            Ok((rem, offset))
        } else {
            Err(nom::Err::Error(NomError::new(
                rem,
                nom::error::ErrorKind::Verify,
            )))
        }
    }

    pub fn parse<'b: 'i + 'r, 'i: 'r, 'r>(
        reference_bytes: &'b [u8],
    ) -> impl FnMut(&'i [u8]) -> IResult<(Vec<u8>, Flags<ErrorFlags>)> + 'r {
        move |mut input| {
            let mut current_position = input;
            let mut current_position_is_base = true;
            let mut error_flags = ErrorFlags::none();
            let mut name: Vec<u8> = Vec::new();

            for _ in 0..MAX_LABEL_PARSES {
                if current_position.is_empty() || current_position[0] == b'\0' {
                    break;
                }

                if Name::name_is_compressed(current_position[0]) {
                    match Name::follow_compressed_segment(current_position, reference_bytes) {
                        Ok((rem, offset)) => {
                            if offset == current_position {
                                // If the pointer points to itself, bail out and flag to avoid using MAX_LABEL_PARSES cycles
                                error_flags |= DnsNameInvalidCompression;
                                return Ok((rem, (name, error_flags)));
                            }

                            if current_position_is_base {
                                input = rem;
                                current_position_is_base = false;
                            }
                            current_position = offset;
                        }
                        Err(nom::Err::Error(NomError {
                            input: pos,

                            code: ErrorKind::Verify,
                        })) => {
                            error_flags |= ErrorFlags::DnsNameInvalidCompression;
                            return Ok((pos, (name, error_flags)));
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                } else {
                    let (mut rem, (label, inner_error_flags)) =
                        Name::parse_label(current_position)?;
                    error_flags |= inner_error_flags;

                    if name.len() < DNS_MAX_DOMAIN_LEN {
                        // Truncate the label so the name won't exceed the max length
                        let length =
                            std::cmp::min(label.len(), (DNS_MAX_DOMAIN_LEN - 1) - name.len());
                        // Check if we truncated
                        if name.len() + label.len() + 1 > DNS_MAX_DOMAIN_LEN {
                            error_flags |= ErrorFlags::DnsNameExceedsMaxLen;
                        };
                        // always extend
                        if !name.is_empty() {
                            name.push(b'.');
                        }
                        name.extend_from_slice(&label[..length]);
                    }

                    current_position = rem;

                    if rem.get(0) == Some(&b'\0') {
                        rem = &rem[1..];
                    }

                    if current_position_is_base {
                        input = rem;
                    }
                }
            }
            Ok((input, (name, error_flags)))
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::type_complexity)]

    use crate::name::Name;
    use crate::{ErrorFlags, IResult};
    use rstest::rstest;
    use sawp_flags::{Flag, Flags};

    #[rstest(
    input,
    reference_bytes,
    expected,
    case::parse_simple_name(
        & [
            0x08, 0x73, 0x74, 0x65, 0x72, 0x6c, 0x69, 0x6e, 0x67, 0x08, 0x66, 0x72, 0x65, 0x65,
            0x6e, 0x6f, 0x64, 0x65, 0x03, 0x6e, 0x65, 0x74, 0x00, // sterling.freenode.net
        ],
        & [
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
            b"".as_ref(),
            (
                "sterling.freenode.net".as_bytes().to_vec(),
                ErrorFlags::none()
            )
        ))
    ),
    case::parse_compressed_name(
        & [
            0xc0, 0x0c,
        ],
        & [
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
            b"".as_ref(),
            (
                "sterling.freenode.net".as_bytes().to_vec(),
                ErrorFlags::none()
            )
        ))
    ),
    case::compressed_name_invalid_ptr(
        & [
            0xc0, 0xfc, // answer: invalid ptr
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x27, 0x10, // TTL: 10000
            0x00, 0x04, // Data length: 4
            0xd4, 0xcc, 0xd6, 0x72, // 212.204.214.114
        ],
        & [
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
            [
                0x00, 0x01, // RType: A
                0x00, 0x01, // RClass: IN
                0x00, 0x00, 0x27, 0x10, // TTL: 10000
                0x00, 0x04, // Data length: 4
                0xd4, 0xcc, 0xd6, 0x72, // 212.204.214.114
            ].as_ref(),
            (
                vec![],
                ErrorFlags::DnsNameInvalidCompression.into()
            )
        ))
    ),
    case::too_long_label(
        & [
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
        & [
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
            [
                0x00, 0x01, // RType: A
                0x00, 0x01, // RClass: IN
                0xc0, 0x0c, // answer: AAA.....
                0x00, 0x01, // RType: A
                0x00, 0x01, // RClass: IN
                0x00, 0x00, 0x27, 0x10, // TTL: 10000
                0x00, 0x04, // Data length: 4
                0xd4, 0xcc, 0xd6, 0x72, // 212.204.214.114
            ].as_ref(),
            (
                vec![
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
                ErrorFlags::DnsLabelExceedsMaxLen.into()
            )
        ))
    ),
    case::too_long_name(
        & [
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
        & [
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
            [
                0x00, 0x01, // RType: A
                0x00, 0x01, // RClass: IN
                0xc0, 0x0c, // answer: sterling.freenode.net
                0x00, 0x01, // RType: A
                0x00, 0x01, // RClass: IN
                0x00, 0x00, 0x27, 0x10, // TTL: 10000
                0x00, 0x04, // Data length: 4
                0xd4, 0xcc, 0xd6, 0x72, // 212.204.214.114
            ].as_ref(),
            (
                "sterling.freenode.net\
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
                .sterling.free".as_bytes().to_vec(),
                ErrorFlags::DnsNameExceedsMaxLen.into()
            )
        ))
    ),
    case::self_referential_ptr(
        & [
            0xc0, 0x27, // ptr to this location
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x27, 0x10, // TTL: 10000
            0x00, 0x04, // Data length: 4
            0xd4, 0xcc, 0xd6, 0x72, // 212.204.214.114
        ],
        & [
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
            0xc0, 0x27, // ptr to this location
            0x00, 0x01, // RType: A
            0x00, 0x01, // RClass: IN
            0x00, 0x00, 0x27, 0x10, // TTL: 10000
            0x00, 0x04, // Data length: 4
            0xd4, 0xcc, 0xd6, 0x72, // 212.204.214.114
        ],
        Ok((
            [
                0x00, 0x01, // RType: A
                0x00, 0x01, // RClass: IN
                0x00, 0x00, 0x27, 0x10, // TTL: 10000
                0x00, 0x04, // Data length: 4
                0xd4, 0xcc, 0xd6, 0x72, // 212.204.214.114
            ].as_ref(),
            (
                vec![],
                ErrorFlags::DnsNameInvalidCompression.into()
            )
        ))
    ),
    )]
    fn name(input: &[u8], reference_bytes: &[u8], expected: IResult<(Vec<u8>, Flags<ErrorFlags>)>) {
        assert_eq!(Name::parse(reference_bytes)(input), expected);
    }
}
