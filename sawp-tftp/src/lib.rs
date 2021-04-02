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

#![allow(clippy::upper_case_acronyms)]

use sawp::error::{Error, Result};
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

/// The TFTP header of a packet contains the  opcode  associated  with
/// that packet. TFTP supports five types of packets
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive)]
#[repr(u16)]
pub enum OpCode {
    ReadRequest = 1,
    WriteRequest = 2,
    Data = 3,
    Acknowledgement = 4,
    Error = 5,
}

#[derive(Debug, PartialEq)]
pub enum Mode {
    NetASCII,
    Mail,
    Octet,
    Unknown(String),
}

///  The error code is an integer indicating the nature of the error.
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive)]
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
    Unknown = 65535,
}

/// Represents the various types of TFTP Packets
#[derive(Debug, PartialEq)]
pub enum Packet {
    ReadWriteRequest {
        filename: String,
        mode: Mode,
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
}

/// Breakdown of the parsed TFTP bytes
#[derive(Debug, PartialEq)]
pub struct Message {
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
                    (
                        input,
                        Packet::ReadWriteRequest {
                            filename: filename.into(),
                            mode,
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
            };
            Ok((input, Some(Message { op_code, packet })))
        } else {
            Err(Error::from(nom::Err::Error((input, ErrorKind::IsA))))
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
        case::hello_world(b"hello world", Err(error::Error::from(nom::Err::Error((b"hello world" as &[u8], ErrorKind::Tag))))),
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
