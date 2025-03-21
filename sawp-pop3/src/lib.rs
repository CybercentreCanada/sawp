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

use nom::branch::alt;
/// Re-export of the `Flags` struct that is used to represent bit flags
/// in this crate.
pub use sawp_flags::{Flag, Flags};

use sawp::error::{Error, ErrorKind, Needed, Result};
use sawp::parser::{Direction, Parse};
use sawp::probe::{Probe, Status as ProbeStatus};
use sawp::protocol::Protocol;
use sawp_flags::BitFlags;

/// FFI structs and Accessors
#[cfg(feature = "ffi")]
mod ffi;

#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

use nom::bytes::streaming::tag;
use nom::character::streaming::{alpha1, char, crlf, not_line_ending, space1};
use nom::combinator::{eof, map, opt, peek};
use nom::multi::many_till;
use nom::sequence::{delimited, terminated};
use std::convert::TryFrom;

pub const CRLF: &[u8] = b"\r\n";
pub const SPACE: &[u8] = b" ";
pub const CLIENT_COMMAND_MAX_LEN: usize = 256;
pub const SERVER_RESP_FIRST_LINE_MAX_LEN: usize = 512;

/// The supported POP3 client commands
#[derive(Debug, PartialEq, Eq)]
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
    STLS,
    AUTH,
    SASL,
    Unknown(String),
}

/// POP3 servers can respond with either an OK or Error response based on client input
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_pop3"))]
pub enum Status {
    OK,
    ERR,
}

/// Parser-identified errors that are not fatal
#[repr(u8)]
#[derive(Debug, Copy, Clone, BitFlags, PartialEq, Eq)]
pub enum ErrorFlag {
    /// Command + space + argument + CRLF must not exceed 255 octets (RFC 2449)
    CommandTooLong = 0b0000_0001,
    /// Number of arguments doesn't match the command
    IncorrectArgumentNum = 0b0000_0010,
    /// Correct keyword format, but unknown value
    UnknownKeyword = 0b0000_0100,
    /// First line of server response + CRLF must not exceed 512 octets (RFC 2449)
    ResponseTooLong = 0b0000_1000,
}

impl TryFrom<&[u8]> for Keyword {
    type Error = Error;

    fn try_from(cmd: &[u8]) -> Result<Self> {
        if cmd.is_empty() {
            Err(Error::parse(Some("Empty Keyword".to_string())))
        } else {
            match cmd {
                b"QUIT" => Ok(Keyword::QUIT),
                b"STAT" => Ok(Keyword::STAT),
                b"LIST" => Ok(Keyword::LIST),
                b"RETR" => Ok(Keyword::RETR),
                b"DELE" => Ok(Keyword::DELE),
                b"NOOP" => Ok(Keyword::NOOP),
                b"RSET" => Ok(Keyword::RSET),
                b"TOP" => Ok(Keyword::TOP),
                b"UIDL" => Ok(Keyword::UIDL),
                b"USER" => Ok(Keyword::USER),
                b"PASS" => Ok(Keyword::PASS),
                b"APOP" => Ok(Keyword::APOP),
                b"CAPA" => Ok(Keyword::CAPA),
                b"STLS" => Ok(Keyword::STLS),
                b"AUTH" => Ok(Keyword::AUTH),
                b"SASL" => Ok(Keyword::SASL),
                _ => Ok(Keyword::Unknown(std::str::from_utf8(cmd).unwrap().into())),
            }
        }
    }
}

impl std::fmt::Display for Keyword {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.write_str(match self {
            Keyword::QUIT => "QUIT",
            Keyword::STAT => "STAT",
            Keyword::LIST => "LIST",
            Keyword::RETR => "RETR",
            Keyword::DELE => "DELE",
            Keyword::NOOP => "NOOP",
            Keyword::RSET => "RSET",
            Keyword::TOP => "TOP",
            Keyword::UIDL => "UIDL",
            Keyword::USER => "USER",
            Keyword::PASS => "PASS",
            Keyword::APOP => "APOP",
            Keyword::CAPA => "CAPA",
            Keyword::STLS => "STLS",
            Keyword::AUTH => "AUTH",
            Keyword::SASL => "SASL",
            Keyword::Unknown(keyword) => keyword,
        })
    }
}

impl TryFrom<&[u8]> for Status {
    type Error = Error;

    fn try_from(status: &[u8]) -> Result<Self> {
        match status {
            b"+OK" => Ok(Status::OK),
            b"-ERR" => Ok(Status::ERR),
            _ => Err(Error::parse(Some("Unknown Status".to_string()))),
        }
    }
}

impl Status {
    pub fn to_str(&self) -> &'static str {
        match self {
            Status::OK => "OK",
            Status::ERR => "ERR",
        }
    }
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_pop3"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    pub keyword: Keyword,
    pub args: Vec<Vec<u8>>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_pop3"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub status: Status,
    pub header: Vec<u8>,
    pub data: Vec<Vec<u8>>,
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_pop3"))]
#[derive(Debug, PartialEq, Eq)]
pub enum InnerMessage {
    Command(Command),
    Response(Response),
}

#[cfg_attr(feature = "ffi", derive(GenerateFFI), sawp_ffi(prefix = "sawp_pop3"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    pub error_flags: Flags<ErrorFlag>,
    pub inner: InnerMessage,
}

pub struct POP3 {}

impl<'a> Probe<'a> for POP3 {
    fn probe(&self, input: &'a [u8], direction: Direction) -> ProbeStatus {
        match self.parse(input, direction) {
            Ok((_, Some(msg))) => {
                if msg.error_flags == ErrorFlag::none() {
                    ProbeStatus::Recognized
                } else {
                    ProbeStatus::Unrecognized
                }
            }
            Ok((_, _)) => ProbeStatus::Recognized,
            Err(Error {
                kind: ErrorKind::Incomplete(_),
            }) => ProbeStatus::Incomplete,
            Err(_) => ProbeStatus::Unrecognized,
        }
    }
}

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
        command_length + client_payload_length + CRLF.len() > CLIENT_COMMAND_MAX_LEN
    }

    fn parse_response(input: &[u8]) -> Result<(&[u8], Message)> {
        let mut flags: Flags<ErrorFlag> = ErrorFlag::none();

        let (input, raw_status) = terminated(alt((tag("+OK"), tag("-ERR"))), opt(space1))(input)?;
        let status = Status::try_from(raw_status)?;

        let (input, header) = terminated(not_line_ending, crlf)(input)?;
        let header = header.to_vec();

        // This is complicated, because without knowing the command, don't know if response is multiline
        // Will fail in the case that input has only the header, but is a multiline response
        let non_multiline = map(alt((eof, peek(tag("+OK")), peek(tag("-ERR")))), |_| vec![]);
        let multiline = delimited(opt(char('.')), not_line_ending, crlf);
        let multiline_terminator = tag(".\r\n");
        let multilines = map(many_till(multiline, multiline_terminator), |(lines, _)| {
            lines
        });

        let (input, data) = alt((non_multiline, multilines))(input)?;

        let data: Vec<Vec<u8>> = data.iter().map(|x| x.to_vec()).collect();

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

        let (input, raw_keyword) = terminated(alpha1, opt(space1))(input)?;
        let keyword = Keyword::try_from(raw_keyword)?;

        let (input, raw_args) = terminated(not_line_ending, crlf)(input)?;
        let args: Vec<Vec<u8>> = raw_args
            .split(|&x| x == b' ')
            .map(|x| x.to_vec())
            .filter(|x| !x.is_empty())
            .collect();

        let args: Vec<Vec<u8>> = args.iter().map(|x| x.to_vec()).collect();

        // Apply IncorrectArgumentNum flag if necessary, depending on the specific client command used
        match &keyword {
            Keyword::STAT
            | Keyword::NOOP
            | Keyword::RSET
            | Keyword::QUIT
            | Keyword::CAPA
            | Keyword::STLS => {
                if !args.is_empty() {
                    flags |= ErrorFlag::IncorrectArgumentNum;
                }
            }
            Keyword::SASL => {
                if args.is_empty() {
                    flags |= ErrorFlag::IncorrectArgumentNum;
                }
            }
            Keyword::LIST | Keyword::UIDL => match args.len() {
                0 | 1 => {}
                _ => flags |= ErrorFlag::IncorrectArgumentNum,
            },
            Keyword::RETR | Keyword::DELE | Keyword::USER | Keyword::PASS => {
                if args.len() != 1 {
                    flags |= ErrorFlag::IncorrectArgumentNum;
                }
            }
            Keyword::AUTH => match args.len() {
                1 | 2 => {}
                _ => flags |= ErrorFlag::IncorrectArgumentNum,
            },
            Keyword::TOP | Keyword::APOP => {
                if args.len() != 2 {
                    flags |= ErrorFlag::IncorrectArgumentNum;
                }
            }
            Keyword::Unknown(_) => flags |= ErrorFlag::UnknownKeyword,
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
}

impl<'a> Parse<'a> for POP3 {
    fn parse(
        &self,
        input: &'a [u8],
        direction: Direction,
    ) -> Result<(&'a [u8], Option<Self::Message>)> {
        match direction {
            Direction::ToServer => {
                let (input, msg) = POP3::parse_command(input)?;
                Ok((input, Some(msg)))
            }
            Direction::ToClient => {
                let (input, msg) = POP3::parse_response(input)?;
                Ok((input, Some(msg)))
            }
            Direction::Unknown => {
                match (POP3::parse_command(input), POP3::parse_response(input)) {
                    (Ok((input, msg)), _) => Ok((input, Some(msg))),
                    (_, Ok((input, msg))) => Ok((input, Some(msg))),
                    (
                        Err(Error {
                            kind: ErrorKind::Incomplete(req_needed),
                        }),
                        Err(Error {
                            kind: ErrorKind::Incomplete(resp_needed),
                        }),
                    ) => match (req_needed, resp_needed) {
                        (Needed::Unknown, resp) => Err(Error::new(ErrorKind::Incomplete(resp))),
                        (req, Needed::Unknown) => Err(Error::new(ErrorKind::Incomplete(req))),
                        (Needed::Size(req), Needed::Size(resp)) if req < resp => {
                            Err(Error::incomplete_needed(req.into()))
                        }
                        (_, resp) => Err(Error::new(ErrorKind::Incomplete(resp))),
                    },
                    (
                        Err(Error {
                            kind: ErrorKind::Incomplete(size),
                        }),
                        _,
                    ) => Err(Error::new(ErrorKind::Incomplete(size))),
                    (
                        _,
                        Err(Error {
                            kind: ErrorKind::Incomplete(size),
                        }),
                    ) => Err(Error::new(ErrorKind::Incomplete(size))),
                    (Err(e), _) => Err(e), // with no direction and not incomplete, either error is as good as the other
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use sawp::error::{Error, NomError};

    #[test]
    fn test_name() {
        assert_eq!(POP3::name(), "pop3");
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Err(Error::incomplete_needed(3))),
        case::incomplete_ok(b"+OK", Err(Error::incomplete_needed(1))),
        case::incomplete_err(b"-ERR ", Err(Error::incomplete_needed(1))),
        case::ok(
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
        case::multiple_responses(b"+OK 2 200\r\n+OK 3 300\r\n",
            Ok((b"+OK 3 300\r\n".as_ref(),
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
    case::multiline(
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
    case::multline_byte_stuffing(
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
    case::incomplete_multiline(
        b"+OK Capability list follows\r\nTOP\r\n",
        Err(Error::incomplete_needed(3))
    ),
    case::too_long(
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
        Err(Error::from(NomError::new(b"" as &[u8], nom::error::ErrorKind::Tag)))),
    )]
    fn test_parse_response(input: &[u8], expected: Result<(&[u8], Option<Message>)>) {
        let pop3 = POP3 {};
        assert_eq!(pop3.parse(input, Direction::ToClient), expected);
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Err(Error::incomplete_needed(1))),
        case::incomplete(b"TOP", Err(Error::incomplete_needed(1))),
        case::unknown_keyword(
            b"HELLO WORLD\r\n", 
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::UnknownKeyword.into(),
                        inner: InnerMessage::Command(Command {
                            keyword: Keyword::Unknown("HELLO".into()),
                            args: vec![
                                b"WORLD".to_vec(),
                            ],
                        }),
                    },
                ),
            ))),
        case::invalid_keyword(
            b"\x01\x02\x03\0x04 WORLD\r\n", 
            Err(Error::from(NomError::new(b"" as &[u8], nom::error::ErrorKind::Alpha)))),
        case::no_args(
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
        case::one_arg(
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
        case::two_args(
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
        case::non_alphanum_args(b"USER moises.nunez@ingenierianumar.com\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::none(),
                        inner: InnerMessage::Command(Command {
                            keyword: Keyword::USER,
                            args: vec![
                                b"moises.nunez@ingenierianumar.com".to_vec(),
                            ],
                        }),
                    },
                ),
            ))),
        case::too_long(
            b"PASS 12345678901234567890123456789012345678901234567890\
            123456789012345678901234567890123456789012345678901234567890\
            123456789012345678901234567890123456789012345678901234567890\
            123456789012345678901234567890123456789012345678901234567890\
            123456789012345678901234567890123456789012345678901234567890\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::CommandTooLong.into(),
                        inner: InnerMessage::Command(Command {
                            keyword: Keyword::PASS,
                            args: vec![
                                b"12345678901234567890123456789012345678901234567890\
                                123456789012345678901234567890123456789012345678901234567890\
                                123456789012345678901234567890123456789012345678901234567890\
                                123456789012345678901234567890123456789012345678901234567890\
                                123456789012345678901234567890123456789012345678901234567890".to_vec(),
                            ],
                        }),
                    },
                ),
            ))),
        case::missing_argument(
            b"DELE\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::IncorrectArgumentNum.into(),
                        inner: InnerMessage::Command(Command {
                            keyword: Keyword::DELE,
                            args: vec![],
                        }),
                    },
                ),
            ))),
        case::missing_argument(
            b"CAPA HELLO WORLD\r\n",
            Ok((b"".as_ref(),
                Some(Message {
                        error_flags: ErrorFlag::IncorrectArgumentNum.into(),
                        inner: InnerMessage::Command(Command {
                            keyword: Keyword::CAPA,
                            args: vec![
                                b"HELLO".to_vec(),
                                b"WORLD".to_vec(),
                            ],
                        }),
                    },
                ),
            ))),
    )]
    fn test_parse_request(input: &[u8], expected: Result<(&[u8], Option<Message>)>) {
        let pop3 = POP3 {};
        assert_eq!(pop3.parse(input, Direction::ToServer), expected);
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", ProbeStatus::Incomplete),
        case::incomplete_request(b"TOP", ProbeStatus::Incomplete),
        case::incomplete_response_ok(b"+OK", ProbeStatus::Incomplete),
        case::incomplete_response_err(b"-ERR", ProbeStatus::Incomplete),
        case::unknown_keyword(b"HELLO WORLD\r\n", ProbeStatus::Unrecognized),
        case::quit(b"QUIT\r\n", ProbeStatus::Recognized),
        case::incorrect_arguments(b"QUIT ARG\r\n", ProbeStatus::Unrecognized),
        case::command_too_long(
            b"PASS 12345678901234567890123456789012345678901234567890\
            123456789012345678901234567890123456789012345678901234567890\
            123456789012345678901234567890123456789012345678901234567890\
            123456789012345678901234567890123456789012345678901234567890\
            123456789012345678901234567890123456789012345678901234567890\r\n",
            ProbeStatus::Unrecognized
        ),
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
            ProbeStatus::Unrecognized
        )
    )]
    fn test_probe(input: &[u8], expected: ProbeStatus) {
        let pop3 = POP3 {};
        assert_eq!(pop3.probe(input, Direction::Unknown), expected);
    }
}
