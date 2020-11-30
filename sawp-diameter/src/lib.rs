//! Protocol References:
//!     https://tools.ietf.org/html/rfc6733

use sawp::error::Result;
use sawp::parser::Parse;
use sawp::protocol::Protocol;

use nom::bytes::streaming::tag;
use nom::bytes::streaming::take;
use nom::combinator;
use nom::error::{Error, ErrorKind};
use nom::multi::many0;
use nom::number::streaming::{be_u24, be_u32, be_u8};
use nom::IResult;

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

#[derive(Debug, PartialEq)]
pub struct AVP {
    code: u32,
    flags: u8,
    length: u32, // Actually u24
    vendor_id: Option<u32>,
    data: Vec<u8>, // TODO add help functions to convert to Derived Data Formats (Address, Time, ...)
    padding: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct Message {
    header: Header,
    avps: Vec<AVP>,
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
            Err(nom::Err::Error(Error::new(input, ErrorKind::LengthValue)))
        } else if len > (input.len() + read) {
            Err(nom::Err::Incomplete(nom::Needed::new(
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
    pub fn reserved_set(&self) -> bool {
        self.get_reserved() != 0
    }

    pub fn get_reserved(&self) -> u8 {
        self.flags & Self::RESERVED_MASK
    }

    /// Length of AVPs
    pub fn length(&self) -> usize {
        (self.length as usize) - Self::SIZE
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, version) = tag(&[1u8])(input)?;
        let (input, length) = length(Self::PRE_LENGTH_SIZE)(input)?;
        if (length as usize) < Self::SIZE {
            return Err(nom::Err::Error(Error::new(input, ErrorKind::LengthValue)));
        }
        let (input, flags) = be_u8(input)?;
        let (input, code) = be_u24(input)?;
        let (input, app_id) = be_u32(input)?;
        let (input, hop_id) = be_u32(input)?;
        let (input, end_id) = be_u32(input)?;

        Ok((
            input,
            Self {
                version: version[0],
                length,
                flags,
                code,
                app_id,
                hop_id,
                end_id,
            },
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
    pub fn reserved_set(&self) -> bool {
        self.get_reserved() != 0
    }

    pub fn get_reserved(&self) -> u8 {
        self.flags & Self::RESERVED_MASK
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, code) = be_u32(input)?;
        let (input, flags) = be_u8(input)?;
        let (input, length) = length(Self::PRE_LENGTH_SIZE)(input)?;
        let header_size = if Self::vendor_specific_flag(flags) {
            Self::PRE_LENGTH_SIZE + 4
        } else {
            Self::PRE_LENGTH_SIZE
        };
        if (length as usize) < header_size {
            return Err(nom::Err::Error(Error::new(input, ErrorKind::LengthValue)));
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
        Ok((
            input,
            Self {
                code,
                flags,
                length,
                vendor_id,
                data: data.into(),
                padding: padding.into(),
            },
        ))
    }
}

impl Protocol<'_> for Diameter {
    type Message = Message;

    fn name() -> &'static str {
        "diameter"
    }
}

impl<'a> Parse<'a> for Diameter {
    fn parse(&self, input: &'a [u8]) -> Result<(&'a [u8], Option<Self::Message>)> {
        let (input, header) = Header::parse(input)?;

        // Don't have to worry about splitting slice causing incomplete
        // Because we have verified the length in Header::parse
        let (input, avps_input) = combinator::complete(take(header.length()))(input)?;
        let (rest, avps) = many0(combinator::complete(AVP::parse))(avps_input)?;
        if !rest.is_empty() {
            // many0 will stop if subparser fails, but should read all
            Err(nom::Err::Error(Error::new(avps_input, ErrorKind::Many0)).into())
        } else {
            Ok((input, Some(Message { header, avps })))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use sawp::error;

    #[test]
    fn test_name() {
        assert_eq!(Diameter::name(), "diameter");
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Err(nom::Err::Incomplete(nom::Needed::new(1)))),
        case::hello_world(b"hello world", Err(nom::Err::Error(Error::new(b"hello world" as &[u8], ErrorKind::Tag)))),
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
            Err(nom::Err::Error(Error::new(
                &[
                    // Flags: 128 (Request)
                    0x80 as u8,
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
            Ok((&[] as &[u8], Header {
                version: 1,
                length: 20,
                flags: 128,
                code: 257,
                app_id: 0,
                hop_id: 0x53c_afe6a,
                end_id: 0x7dc_0a11b,
            }))
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
            Err(nom::Err::Incomplete(nom::Needed::new(4)))
        ),
    )]
    #[test]
    fn test_header(input: &[u8], expected: IResult<&[u8], Header>) {
        assert_eq!(Header::parse(input), expected);
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Err(nom::Err::Incomplete(nom::Needed::new(4)))),
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
            Ok((&[] as &[u8], AVP {
                code: 264,
                flags: 0x40,
                length: 31,
                vendor_id: None,
                data: (b"backend.eap.testbed.aaa" as &[u8]).into(),
                padding: vec![0x00],
            }))
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
            Ok((&[] as &[u8], AVP {
                code: 264,
                flags: 0x80,
                length: 12,
                vendor_id: Some(1_234_567_890u32),
                data: Vec::new(),
                padding: Vec::new(),
            }))
        ),
    )]
    #[test]
    fn test_avp(input: &[u8], expected: IResult<&[u8], AVP>) {
        assert_eq!(AVP::parse(input), expected);
    }

    //TODO test AVP flags and codes

    #[rstest(
        input,
        expected,
        case::empty(b"", Err(error::Error { kind: error::ErrorKind::Incomplete(nom::Needed::new(1)) })),
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
                        hop_id: 0x53c_afe6a,
                        end_id: 0x7dc_0a11b,
                    },
                    avps: Vec::new(),
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
                    flags: 128,
                    code: 257,
                    app_id: 0,
                    hop_id: 0x53c_afe6a,
                    end_id: 0x7dc_0a11b,
                },
                avps: vec![
                    AVP {
                        code: 264,
                        flags: 0x40,
                        length: 31,
                        vendor_id: None,
                        data: (b"backend.eap.testbed.aaa" as &[u8]).into(),
                        padding: vec![0x00],
                    },
                    AVP {
                        code: 264,
                        flags: 0x80,
                        length: 12,
                        vendor_id: Some(1_234_567_890u32),
                        data: Vec::new(),
                        padding: Vec::new(),
                    },
                ],
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
            Err(error::Error { kind: error::ErrorKind::Incomplete(nom::Needed::new(2)) })
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
            Err(error::Error::new(error::ErrorKind::Nom(ErrorKind::Many0))),
        ),
    )]
    #[test]
    fn test_diameter(input: &[u8], expected: Result<(&[u8], Option<Message>)>) {
        let diameter = Diameter {};

        assert_eq!(diameter.parse(input), expected);
    }
}
