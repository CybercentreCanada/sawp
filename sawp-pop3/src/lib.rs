//! A POP3 protocol parser. Given bytes and a [`sawp::parser::Direction`], it will
//! attempt to parse the bytes and return a [`Message`]. The parser will
//! inform the caller about what went wrong if no message is returned (see [`sawp::parser::Parse`]
//! for details on possible return types).
//!
//! The following protocol references were used to create this module:
//!
//! [RFC 1939 - Post Office Protocol Version 3](https://www.ietf.org/rfc/rfc1939.txt)
//! [RFC 2449 - POP3 Extension Mechanism](https://datatracker.ietf.org/doc/html/rfc2449)
//!
//! # Example
//! ```
//! use sawp::parser::{Direction, Parse};
//! use sawp::error::Error;
//! use sawp_flags::Flag;
//! use sawp_pop3::{POP3, Message, InnerMessage, ErrorFlag};
//!
//! fn parse_bytes(input: &[u8]) -> std::result::Result<&[u8], Error> {
//!     let pop3 = POP3 {};
//!     let mut bytes = input;
//!     while bytes.len() > 0 {
//!         match pop3.parse(bytes, Direction::Unknown) {
//!             // The parser succeeded and returned the remaining bytes and the parsed POP3 message
//!             Ok((rest, Some(message))) => {
//!                 bytes = rest;
//!                 // Message violates POP3 standard in some way
//!                 if message.error_flags != ErrorFlag::none() {
//!                     println!("Error flags: {:?}", message.error_flags);
//!                 }
//!
//!                 match message.inner {
//!                     // Command sent by client
//!                     InnerMessage::Command(_) => println!("POP3 Command {:?}", message.inner),
//!                     // Response sent by server
//!                     InnerMessage::Response(_) => println!("POP3 Response {:?}", message.inner),
//!                     // Empty input
//!                     InnerMessage::None => {},
//!                 }
//!             }
//!             // This should never occur with POP3 but is included for consistency with other parsers
//!             Ok((_rest, None)) => {}
//!             // The parser determined that this was not POP3
//!             Err(e) => return Err(e),
//!         }
//!     }
//!
//!     Ok(bytes)
//! }
//! ```

use sawp::error::Result;
use sawp::parser::{Direction, Parse};
use sawp::probe::Probe;
use sawp::protocol::Protocol;
use sawp_flags::{BitFlags, Flag, Flags};

/// FFI structs and Accessors
#[cfg(feature = "ffi")]
mod ffi;

#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

use nom::bytes::complete::{is_not, take_until};
use nom::character::complete::{char, crlf};
use nom::combinator::opt;
use nom::multi::many_till;
use nom::sequence::{pair, preceded, terminated};

pub const CRLF: &[u8] = b"\r\n";
pub const SPACE: &[u8] = b" ";
pub const CLIENT_COMMAND_MAX_LEN: usize = 256;
pub const SERVER_RESP_FIRST_LINE_MAX_LEN: usize = 512;

/// The supported POP3 client commands
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_pop3"))]
pub enum Keyword {
    QUIT,
    STAT,
    LIST,
    RETR,
    DELE,
    NOOP,
    RSET,
    TOP,
    UIDL,
    USER,
    PASS,
    APOP,
    CAPA,
    Unknown(Vec<u8>),
}

/// POP3 servers can respond with either an OK or Error response based on client input
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_pop3"))]
pub enum Status {
    OK,
    ERR,
    Unknown(Vec<u8>),
}

/// Parser-identified errors that are not fatal
#[repr(u8)]
#[derive(Debug, Copy, Clone, BitFlags, PartialEq)]
pub enum ErrorFlag {
    /// Command + space + argument + CRLF must not exceed 255 octets (RFC 2449)
    CommandTooLong = 0b0000_0001,
    /// Some commands require 1 or 2 mandatory arguments to be specified by the client
    MissingArgument = 0b0000_0010,
    /// First word in client-to-server payload was not a recognized keyword
    InvalidKeyword = 0b0000_0100,
    /// First line of server response + CRLF must not exceed 512 octets (RFC 2449)
    ResponseTooLong = 0b0000_1000,
    EmptyInput = 0b0001_0000,
    /// First word in server-to-client payload was not a recognized status (+OK or -ERR)
    InvalidStatus = 0b0010_0000,
}

impl Keyword {
    fn from_raw(cmd: &[u8]) -> Self {
        match cmd {
            b"QUIT" => Keyword::QUIT,
            b"STAT" => Keyword::STAT,
            b"LIST" => Keyword::LIST,
            b"RETR" => Keyword::RETR,
            b"DELE" => Keyword::DELE,
            b"NOOP" => Keyword::NOOP,
            b"RSET" => Keyword::RSET,
            b"TOP" => Keyword::TOP,
            b"UIDL" => Keyword::UIDL,
            b"USER" => Keyword::USER,
            b"PASS" => Keyword::PASS,
            b"APOP" => Keyword::APOP,
            b"CAPA" => Keyword::CAPA,
            _ => Keyword::Unknown(cmd.to_vec()),
        }
    }
}

impl Status {
    fn from_raw(status: &[u8]) -> Self {
        match status {
            b"+OK" => Status::OK,
            b"-ERR" => Status::ERR,
            _ => Status::Unknown(status.to_vec()),
        }
    }
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_pop3"))]
#[derive(Debug, PartialEq)]
pub struct Command {
    pub keyword: Keyword,
    pub args: Vec<Vec<u8>>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_pop3"))]
#[derive(Debug, PartialEq)]
pub struct Response {
    pub status: Status,
    pub header: Vec<u8>,
    pub data: Vec<Vec<u8>>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_pop3"))]
#[derive(Debug, PartialEq)]
pub enum InnerMessage {
    Command(Command),
    Response(Response),
    None,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_pop3"))]
#[derive(Debug, PartialEq)]
pub struct Message {
    pub error_flags: Flags<ErrorFlag>,
    pub inner: InnerMessage,
}

pub struct POP3 {}

impl<'a> Probe<'a> for POP3 {}

impl Protocol<'_> for POP3 {
    type Message = Message;

    fn name() -> &'static str {
        "pop3"
    }
}

impl POP3 {
    fn server_response_too_long(status_length: usize, payload_first_line_length: usize) -> bool {
        status_length + SPACE.len() + payload_first_line_length + CRLF.len()
            > SERVER_RESP_FIRST_LINE_MAX_LEN
    }

    fn client_command_too_long(command_length: usize, client_payload_length: usize) -> bool {
        command_length + SPACE.len() + client_payload_length + CRLF.len() > CLIENT_COMMAND_MAX_LEN
    }

    fn parse_response(input: &[u8]) -> Result<(&[u8], Message)> {
        let mut flags: Flags<ErrorFlag> = ErrorFlag::none();

        let (input, raw_status) = terminated(is_not(" \r"), opt(char(' ')))(input)?;
        let status = Status::from_raw(raw_status);

        let first_line = terminated(take_until(CRLF), crlf);
        let additional_line = terminated(preceded(opt(char('.')), take_until(CRLF)), crlf);
        let termination_line = pair(char('.'), crlf);
        let (input, (header, data)) = pair(
            first_line,
            opt(many_till(additional_line, termination_line)),
        )(input)?;

        let header = header.to_vec();
        let data: Vec<Vec<u8>> = match data {
            None => vec![],
            Some((x, _)) => x.iter().map(|x| x.to_vec()).collect(),
        };

        if let Status::Unknown(_) = status {
            flags |= ErrorFlag::InvalidStatus;
        }

        if POP3::server_response_too_long(raw_status.len(), header.len()) {
            flags |= ErrorFlag::ResponseTooLong;
        }

        let message = Message {
            error_flags: flags,
            inner: InnerMessage::Response(Response {
                status,
                header,
                data,
            }),
        };

        Ok((input, message))
    }

    fn parse_command(input: &[u8]) -> Result<(&[u8], Message)> {
        let mut flags: Flags<ErrorFlag> = ErrorFlag::none();

        let (input, raw_keyword) = terminated(is_not(" \r"), opt(char(' ')))(input)?;
        let keyword = Keyword::from_raw(raw_keyword);

        let (input, raw_args) = terminated(take_until(CRLF), crlf)(input)?;
        let args: Vec<Vec<u8>> = raw_args
            .split(|&x| x == b' ')
            .map(|x| x.to_vec())
            .filter(|x| !x.is_empty())
            .collect();

        // Apply MissingArgument flag if necessary, depending on the specific client command used
        match keyword {
            Keyword::DELE | Keyword::RETR | Keyword::USER | Keyword::PASS => {
                if args.is_empty() {
                    flags |= ErrorFlag::MissingArgument;
                }
            }
            Keyword::TOP | Keyword::APOP => {
                if args.len() < 2 {
                    flags |= ErrorFlag::MissingArgument;
                }
            }
            _ => {}
        }

        if let Keyword::Unknown(_) = keyword {
            flags |= ErrorFlag::InvalidKeyword;
        }

        if POP3::client_command_too_long(raw_keyword.len(), raw_args.len()) {
            flags |= ErrorFlag::CommandTooLong;
        }

        let message = Message {
            error_flags: flags,
            inner: InnerMessage::Command(Command { keyword, args }),
        };

        Ok((input, message))
    }

    fn return_empty_message() -> Result<(&'static [u8], Message)> {
        let mut flags: Flags<ErrorFlag> = ErrorFlag::none();
        flags |= ErrorFlag::EmptyInput;
        let message = Message {
            error_flags: flags,
            inner: InnerMessage::None,
        };

        Ok((b"", message))
    }

    fn parse_data(input: &[u8]) -> Result<(&[u8], Message)> {
        if input.is_empty() {
            POP3::return_empty_message()
        } else if input[0] == b'+' || input[0] == b'-' {
            // Well-formed server responses will always start with + or -
            POP3::parse_response(input)
        } else {
            POP3::parse_command(input)
        }
    }
}

impl<'a> Parse<'a> for POP3 {
    fn parse(
        &self,
        input: &'a [u8],
        _direction: Direction,
    ) -> Result<(&'a [u8], Option<Self::Message>)> {
        let (tail, message) = POP3::parse_data(input)?;

        Ok((tail, Some(message)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn test_name() {
        assert_eq!(POP3::name(), "pop3");
    }

    #[rstest(
        input,
        expected,
        case::empty_input(
            b"",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::EmptyInput.into(),
                        inner: InnerMessage::None,
                    },
                ),
            ))),
        case::client_command_no_args(
            b"CAPA\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::none(),
                        inner: InnerMessage::Command(Command {
                            keyword: Keyword::CAPA,
                            args: vec![],
                        }),
                    },
                ),
            ))),
        case::client_command_one_arg(
            b"DELE 52\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::none(),
                        inner: InnerMessage::Command(Command {
                            keyword: Keyword::DELE,
                            args: vec![
                                b"52".to_vec(),
                            ],
                        }),
                    },
                ),
            ))),
        case::client_command_two_args(
            b"APOP sawp 05aaf79d37225973a00cddaaf568eb96\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::none(),
                        inner: InnerMessage::Command(Command {
                            keyword: Keyword::APOP,
                            args: vec![
                                b"sawp".to_vec(),
                                b"05aaf79d37225973a00cddaaf568eb96".to_vec(),
                            ],
                        }),
                    },
                ),
            ))),
        case::client_command_invalid_keyword(
            b"HELLO SAWP\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::InvalidKeyword.into(),
                        inner: InnerMessage::Command(Command {
                            keyword: Keyword::Unknown(b"HELLO".to_vec()),
                            args: vec![
                                b"SAWP".to_vec(),
                            ],
                        }),
                    },
                ),
            ))),
        case::client_command_too_long(
            b"PASS 12345678901234567890123456789012345678901234567890 \
            123456789012345678901234567890123456789012345678901234567890 \
            123456789012345678901234567890123456789012345678901234567890 \
            123456789012345678901234567890123456789012345678901234567890 \
            123456789012345678901234567890123456789012345678901234567890\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::CommandTooLong.into(),
                        inner: InnerMessage::Command(Command {
                            keyword: Keyword::PASS,
                            args: vec![
                                b"12345678901234567890123456789012345678901234567890".to_vec(),
                                b"123456789012345678901234567890123456789012345678901234567890".to_vec(),
                                b"123456789012345678901234567890123456789012345678901234567890".to_vec(),
                                b"123456789012345678901234567890123456789012345678901234567890".to_vec(),
                                b"123456789012345678901234567890123456789012345678901234567890".to_vec(),
                            ],
                        }),
                    },
                ),
            ))),
        case::client_command_missing_argument(
            b"DELE\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::MissingArgument.into(),
                        inner: InnerMessage::Command(Command {
                            keyword: Keyword::DELE,
                            args: vec![],
                        }),
                    },
                ),
            ))),
        case::server_response(
                b"+OK 2 200\r\n",
                Ok((b"".as_ref(),
                    Some(Message {
                            error_flags: ErrorFlag::none(),
                            inner: InnerMessage::Response(Response {
                                status: Status::OK,
                                header: b"2 200".to_vec(),
                                data: vec![],
                            }),
                        },
                    ),
                ))),
        case::server_response_multiline(
            b"+OK Capability list follows\r\nTOP\r\nUSER\r\nUIDL\r\n.\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::none(),
                        inner: InnerMessage::Response(Response {
                            status: Status::OK,
                            header: b"Capability list follows".to_vec(),
                            data: vec![
                                b"TOP".to_vec(),
                                b"USER".to_vec(),
                                b"UIDL".to_vec(),
                            ],
                        }),
                    },
                ),
            ))),
        case::server_response_multline_byte_stuffing(
            b"+OK 120 octets\r\n\
            Grocery list:\r\n\
            ..6kg of flour\r\n\
            .\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::none(),
                        inner: InnerMessage::Response(Response {
                            status: Status::OK,
                            header: b"120 octets".to_vec(),
                            data: vec![
                                b"Grocery list:".to_vec(),
                                b".6kg of flour".to_vec(),
                            ],
                        }),
                    },
                ),
            ))),
        case::server_response_too_long(
            b"-ERR 12345678901234567890123456789012345678901234567890 \
            123456789012345678901234567890123456789012345678901234567890 \
            123456789012345678901234567890123456789012345678901234567890 \
            123456789012345678901234567890123456789012345678901234567890 \
            123456789012345678901234567890123456789012345678901234567890 \
            123456789012345678901234567890123456789012345678901234567890 \
            123456789012345678901234567890123456789012345678901234567890 \
            123456789012345678901234567890123456789012345678901234567890 \
            123456789012345678901234567890123456789012345678901234567890 \
            123456789012345678901234567890123456789012345678901234567890\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::ResponseTooLong.into(),
                        inner: InnerMessage::Response(Response {
                            status: Status::ERR,
                            header: b"12345678901234567890123456789012345678901234567890 \
                                    123456789012345678901234567890123456789012345678901234567890 \
                                    123456789012345678901234567890123456789012345678901234567890 \
                                    123456789012345678901234567890123456789012345678901234567890 \
                                    123456789012345678901234567890123456789012345678901234567890 \
                                    123456789012345678901234567890123456789012345678901234567890 \
                                    123456789012345678901234567890123456789012345678901234567890 \
                                    123456789012345678901234567890123456789012345678901234567890 \
                                    123456789012345678901234567890123456789012345678901234567890 \
                                    123456789012345678901234567890123456789012345678901234567890"
                                    .to_vec(),
                            data: vec![],
                        }),
                    },
                ),
            ))),
        case::server_response_invalid_status(
            b"+SUCCESS 2 200\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::InvalidStatus.into(),
                        inner: InnerMessage::Response(Response {
                            status: Status::Unknown(b"+SUCCESS".to_vec()),
                            header: b"2 200".to_vec(),
                            data: vec![],
                        }),
                    },
                ),
            ))),
    )]
    fn test_parse(input: &[u8], expected: Result<(&[u8], Option<Message>)>) {
        let pop3 = POP3 {};
        assert_eq!(pop3.parse(input, Direction::Unknown), expected);
    }
}
