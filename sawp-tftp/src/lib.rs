//! A TFTP protocol parser. Given bytes and a [`sawp::parser::Direction`], it will
//! attempt to parse the bytes and return a [`Message`]. The parser will
//! inform the caller about what went wrong if no message is returned (see [`sawp::parser::Parse`]
//! for details on possible return types). TFTP ignores Direction.
//!
//! The following protocol references were used to create this module:
//!
//! [TFTP Protocol (Revision 2)](https://tools.ietf.org/html/rfc1350)
//!
//! # Example
//! ```
//! use sawp::parser::{Direction, Parse};
//! use sawp::error::Error;
//! use sawp::error::ErrorKind;
//! use sawp_tftp::{TFTP, Message};
//!
//! fn parse_bytes(input: &[u8]) -> std::result::Result<&[u8], Error> {
//!     let parser = TFTP {};
//!     let mut bytes = input;
//!     while bytes.len() > 0 {
//!         match parser.parse(bytes, Direction::Unknown) {
//!             // The parser succeeded and returned the remaining bytes and the parsed TFTP message
//!             Ok((rest, Some(message))) => {
//!                 println!("TFTP message: {:?}", message);
//!                 bytes = rest;
//!             }
//!             // The parser recognized that this might be TFTP and made some progress,
//!             // but more bytes are needed
//!             Ok((rest, None)) => return Ok(rest),
//!             // The parser was unable to determine whether this was TFTP or not and more
//!             // bytes are needed
//!             Err(Error { kind: ErrorKind::Incomplete(_) }) => return Ok(bytes),
//!             // The parser determined that this was not TFTP
//!             Err(e) => return Err(e)
//!         }
//!     }
//!
//!     Ok(bytes)
//! }
//! ```

#![allow(clippy::unneeded_field_pattern)]

use sawp::error::{NomError, Result};
use sawp::parser::{Direction, Parse};
use sawp::probe::Probe;
use sawp::protocol::Protocol;

use num_enum::TryFromPrimitive;
use std::convert::TryFrom;

use nom::bytes::streaming::{tag, take_while};
use nom::combinator::map_res;
use nom::error::ErrorKind;
use nom::number::streaming::be_u16;
use nom::sequence::terminated;

/// FFI structs and Accessors
#[cfg(feature = "ffi")]
mod ffi;

#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

/// The TFTP header of a packet contains the  opcode  associated  with
/// that packet. TFTP supports five types of packets
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum OpCode {
    ReadRequest = 1,
    WriteRequest = 2,
    Data = 3,
    Acknowledgement = 4,
    Error = 5,
    OptionAcknowledgement = 6,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_tftp"))]
#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    NetASCII,
    Mail,
    Octet,
    Unknown(String),
}

///  The error code is an integer indicating the nature of the error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum ErrorCode {
    NotDefined = 0,
    FileNotFound = 1,
    AccessViolation = 2,
    DiskFull = 3,
    IllegalTFTPOperation = 4,
    UnknownTransferId = 5,
    FileAlreadyExists = 6,
    NoSuchUser = 7,
    OptionRejected = 8,
    Unknown = 65535,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_tftp"))]
#[derive(Debug, PartialEq, Eq)]
pub struct OptionExtension {
    pub name: String,
    pub value: String,
}

/// Represents the various types of TFTP Packets
#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_tftp"))]
#[derive(Debug, PartialEq, Eq)]
pub enum Packet {
    ReadWriteRequest {
        filename: String,
        mode: Mode,
        options: Vec<OptionExtension>,
    },
    Data {
        block_number: u16,
        data: Vec<u8>,
    },
    Ack(u16),
    Error {
        raw_code: u16,
        code: ErrorCode,
        message: String,
    },
    OptAck(Vec<OptionExtension>),
}

/// Breakdown of the parsed TFTP bytes
#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_tftp"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    #[cfg_attr(feature = "ffi", sawp_ffi(copy))]
    pub op_code: OpCode,
    pub packet: Packet,
}

#[derive(Debug)]
pub struct TFTP {}

impl<'a> Probe<'a> for TFTP {}

impl Protocol<'_> for TFTP {
    type Message = Message;

    fn name() -> &'static str {
        "tftp"
    }
}

fn parse_options(input: &'_ [u8]) -> Result<(&'_ [u8], Vec<OptionExtension>)> {
    let mut bytes = input;
    let mut options: Vec<OptionExtension> = Vec::new();
    while !bytes.is_empty() {
        let (rest, name) = map_res(
            terminated(take_while(|c| c != 0), tag(&[0])),
            std::str::from_utf8,
        )(bytes)?;
        let (rest, value) = map_res(
            terminated(take_while(|c| c != 0), tag(&[0])),
            std::str::from_utf8,
        )(rest)?;
        options.push(OptionExtension {
            name: name.into(),
            value: value.into(),
        });
        bytes = rest;
    }

    Ok((bytes, options))
}

impl<'a> Parse<'a> for TFTP {
    fn parse(
        &self,
        input: &'a [u8],
        _direction: Direction,
    ) -> Result<(&'a [u8], Option<Self::Message>)> {
        let (input, op_code) = be_u16(input)?;
        if let Ok(op_code) = OpCode::try_from(op_code) {
            let (input, packet) = match op_code {
                OpCode::ReadRequest | OpCode::WriteRequest => {
                    let (input, filename) = map_res(
                        terminated(take_while(|c| c != 0), tag(&[0])),
                        std::str::from_utf8,
                    )(input)?;
                    let (input, mode) = map_res(
                        terminated(take_while(|c| c != 0), tag(&[0])),
                        std::str::from_utf8,
                    )(input)?;
                    let mode = match &mode.to_lowercase()[..] {
                        "netascii" => Mode::NetASCII,
                        "octet" => Mode::Octet,
                        "mail" => Mode::Mail,
                        _ => Mode::Unknown(mode.into()),
                    };

                    let (input, options) = match parse_options(input) {
                        Ok((input, options)) => (input, options),
                        _ => (input, Vec::new()),
                    };

                    (
                        input,
                        Packet::ReadWriteRequest {
                            filename: filename.into(),
                            mode,
                            options,
                        },
                    )
                }
                OpCode::Data => {
                    let (input, block_number) = be_u16(input)?;
                    (
                        &[] as &[u8],
                        Packet::Data {
                            block_number,
                            data: input.into(),
                        },
                    )
                }
                OpCode::Acknowledgement => {
                    let (input, block_number) = be_u16(input)?;
                    (input, Packet::Ack(block_number))
                }
                OpCode::Error => {
                    let (input, raw_code) = be_u16(input)?;
                    let (input, message) = map_res(
                        terminated(take_while(|c| c != 0), tag(&[0])),
                        std::str::from_utf8,
                    )(input)?;

                    let code = ErrorCode::try_from(raw_code).unwrap_or(ErrorCode::Unknown);
                    (
                        input,
                        Packet::Error {
                            raw_code,
                            code,
                            message: message.into(),
                        },
                    )
                }
                OpCode::OptionAcknowledgement => match parse_options(input) {
                    Ok((input, options)) => (input, Packet::OptAck(options)),
                    _ => (input, Packet::OptAck(Vec::new())),
                },
            };
            Ok((input, Some(Message { op_code, packet })))
        } else {
            Err(NomError::new(input, ErrorKind::IsA).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use sawp::error;
    use sawp::probe::Status;

    #[test]
    fn test_name() {
        assert_eq!(TFTP::name(), "tftp");
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Err(error::Error::incomplete_needed(2))),
        case::hello_world(b"hello world", Err(NomError::new(b"hello world", ErrorKind::Tag).into())),
        case::read(
            &[
                // OpCode: 1 (Read)
                0x00, 0x01,
                // Read
                // Filename: log.txt
                0x6c, 0x6f, 0x67, 0x2e, 0x74, 0x78, 0x74, 0x00,
                // Mode: netascii
                0x6e, 0x65, 0x74, 0x61, 0x73, 0x63, 0x69, 0x69, 0x00,
            ],
            Ok((&[] as &[u8],
                Some(Message {
                    op_code: OpCode::ReadRequest,
                    packet: Packet::ReadWriteRequest {
                        filename: String::from("log.txt"),
                        mode: Mode::NetASCII,
                        options: vec![],
                    },
                })))),
        case::opt_read(
            &[
                // OpCode: 1 (Read)
                0x00, 0x01,
                // Read
                // Filename: log.txt
                0x6c, 0x6f, 0x67, 0x2e, 0x74, 0x78, 0x74, 0x00,
                // Mode: netascii
                0x6e, 0x65, 0x74, 0x61, 0x73, 0x63, 0x69, 0x69, 0x00,
                // Options
                // Option name: tsize
                0x74, 0x73, 0x69, 0x7a, 0x65, 0x00,
                // Option value: 0
                0x30, 0x00,
            ],
            Ok((&[] as &[u8],
                Some(Message {
                    op_code: OpCode::ReadRequest,
                    packet: Packet::ReadWriteRequest {
                        filename: String::from("log.txt"),
                        mode: Mode::NetASCII,
                        options: vec![
                            OptionExtension {
                                name: String::from("tsize"),
                                value: String::from("0"),
                            }
                        ],
                    },
                })))),
        case::write(
            &[
                // OpCode: 2 (Write)
                0x00, 0x02,
                // Write
                // Filename: log.txt
                0x6c, 0x6f, 0x67, 0x2e, 0x74, 0x78, 0x74, 0x00,
                // Mode: octet
                0x4f, 0x63, 0x54, 0x65, 0x54, 0x00,
            ],
            Ok((&[] as &[u8],
                Some(Message {
                    op_code: OpCode::WriteRequest,
                    packet: Packet::ReadWriteRequest {
                        filename: String::from("log.txt"),
                        mode: Mode::Octet,
                        options: vec![],
                    },
                })))),
        case::opt_write(
            &[
                // OpCode: 2 (Write)
                0x00, 0x02,
                // Write
                // Filename: log.txt
                0x6c, 0x6f, 0x67, 0x2e, 0x74, 0x78, 0x74, 0x00,
                // Mode: octet
                0x4f, 0x63, 0x54, 0x65, 0x54, 0x00,
                // Options
                // Option name: tsize
                0x74, 0x73, 0x69, 0x7a, 0x65, 0x00,
                // Option value: 0
                0x30, 0x00,
                // Option name: blksize
                0x62, 0x6c, 0x6b, 0x73, 0x69, 0x7a, 0x65, 0x00,
                // Option value: 1432
                0x31, 0x34, 0x33, 0x32, 0x00,
            ],
            Ok((&[] as &[u8],
                Some(Message {
                    op_code: OpCode::WriteRequest,
                    packet: Packet::ReadWriteRequest {
                        filename: String::from("log.txt"),
                        mode: Mode::Octet,
                        options: vec![
                            OptionExtension {
                                name: String::from("tsize"),
                                value: String::from("0"),
                            },
                            OptionExtension {
                                name: String::from("blksize"),
                                value: String::from("1432"),
                            }
                        ],
                    },
                })))),
        case::unknown_mode(
            &[
                // OpCode: 2 (Write)
                0x00, 0x02,
                // Write
                // Filename: log.txt
                0x6c, 0x6f, 0x67, 0x2e, 0x74, 0x78, 0x74, 0x00,
                // Mode: StRaNgEr
                0x53, 0x74, 0x52, 0x61, 0x4e, 0x67, 0x45, 0x72, 0x00,
            ],
            Ok((&[] as &[u8],
                Some(Message {
                    op_code: OpCode::WriteRequest,
                    packet: Packet::ReadWriteRequest {
                        filename: String::from("log.txt"),
                        mode: Mode::Unknown("StRaNgEr".into()),
                        options: vec![],
                    },
                })))),
        case::no_null(
            &[
                // OpCode: 2 (Write)
                0x00, 0x02,
                // Write
                // Filename: log.txt
                0x6c, 0x6f, 0x67, 0x2e, 0x74, 0x78, 0x74, 0x00,
                // Mode: octet (no null termination)
                0x4f, 0x63, 0x54, 0x65, 0x54,
            ],
            Err(error::Error::incomplete_needed(1))),
        case::data(
            &[
                // OpCode: 3 (Data)
                0x00, 0x03,
                // Data
                // Block Number: 12
                0x00, 0x0c,
                // Data
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
            ],
            Ok((&[] as &[u8],
                Some(Message {
                    op_code: OpCode::Data,
                    packet: Packet::Data {
                        block_number: 12,
                        data: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                    },
                })))),
        case::ack(
            &[
                // OpCode: 4 (Acknowledgement)
                0x00, 0x04,
                // Block Number: 16,
                0x00, 0x10,
            ],
            Ok((&[] as &[u8],
                Some(Message {
                   op_code: OpCode::Acknowledgement,
                   packet: Packet::Ack(16),
                })))),
        case::opt_ack(
            &[
                // OpCode: 6 (OptionAcknowledgement)
                0x00, 0x06,
                // Options
                // Option name: tsize
                0x74, 0x73, 0x69, 0x7a, 0x65, 0x00,
                // Option value: 0
                0x30, 0x00,
            ],
            Ok((&[] as &[u8],
                Some(Message {
                    op_code: OpCode::OptionAcknowledgement,
                    packet: Packet::OptAck(
                        vec![OptionExtension {
                            name: String::from("tsize"),
                            value: String::from("0"),
                        }],
                    )
                })))),
        case::error(
            &[
                // OpCode: 5 (Error)
                0x00, 0x05,
                // Error 
                // Code: 3 (DiskFull)
                0x00, 0x03,
                // Message: "Disk full"
                0x44, 0x69, 0x73, 0x6b, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x00,
            ],
            Ok((&[] as &[u8],
                Some(Message {
                    op_code: OpCode::Error,
                    packet: Packet::Error {
                        raw_code: 3,
                        code: ErrorCode::DiskFull,
                        message: String::from("Disk full"),
                    },
                })))),
    )]
    fn test_parse(input: &[u8], expected: Result<(&[u8], Option<Message>)>) {
        let tftp = TFTP {};
        assert_eq!(tftp.parse(input, Direction::Unknown), expected);
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Status::Incomplete),
        case::hello_world(b"hello world", Status::Unrecognized),
        case::header(
        &[
            // OpCode: 1 (Read)
            0x00, 0x01,
            // Read
            // Filename: log.txt
            0x6c, 0x6f, 0x67, 0x2e, 0x74, 0x78, 0x74, 0x00,
            // Mode: netascii
            0x6e, 0x65, 0x74, 0x61, 0x73, 0x63, 0x69, 0x69, 0x00,
        ],
        Status::Recognized
        ),
    )]
    fn test_probe(input: &[u8], expected: Status) {
        let tftp = TFTP {};

        assert_eq!(tftp.probe(input, Direction::Unknown), expected);
    }
}
