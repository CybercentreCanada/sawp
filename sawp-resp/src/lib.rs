//! A RESP protocol parser. Given bytes and a [`sawp::parser::Direction`], it will
//! attempt to parse the bytes and return a [`Message`]. The parser will
//! inform the caller about what went wrong if no message is returned (see [`sawp::parser::Parse`]
//! for details on possible return types).
//!
//! The following protocol references were used to create this module:
//!
//! [RESP Protocol Specification](https://redis.io/topics/protocol)
//!
//! # Example
//! ```
//! use sawp::parser::{Direction, Parse};
//! use sawp::error::Error;
//! use sawp::error::ErrorKind;
//! use sawp_resp::{Resp, Message};
//!
//! fn parse_bytes(input: &[u8]) -> std::result::Result<&[u8], Error> {
//!     let resp = Resp {};
//!     let mut bytes = input;
//!     while bytes.len() > 0 {
//!         // If we know that this is a request or response, change the Direction
//!         // for a more accurate parsing
//!         match resp.parse(bytes, Direction::Unknown) {
//!             // The parser succeeded and returned the remaining bytes and the parsed RESP message
//!             Ok((rest, Some(message))) => {
//!                 println!("Resp message: {:?}", message);
//!                 bytes = rest;
//!             }
//!             // The parser recognized that this might be RESP and made some progress,
//!             // but more bytes are needed
//!             Ok((rest, None)) => return Ok(rest),
//!             // The parser was unable to determine whether this was RESP or not and more
//!             // bytes are needed
//!             Err(Error { kind: ErrorKind::Incomplete(_) }) => return Ok(bytes),
//!             // The parser determined that this was not RESP
//!             Err(e) => return Err(e)
//!         }
//!     }
//!
//!     Ok(bytes)
//! }
//! ```

use sawp::error::Result;
use sawp::parser::{Direction, Parse};
use sawp::probe::{Probe, Status};
use sawp::protocol::Protocol;
use sawp_flags::{BitFlags, Flag, Flags};

use nom::bytes::streaming::{take, take_until};
use nom::character::streaming::crlf;
use nom::number::streaming::be_u8;
use nom::{AsBytes, FindToken, InputTakeAtPosition};

use num_enum::TryFromPrimitive;

use std::convert::TryFrom;

/// FFI structs and Accessors
#[cfg(feature = "ffi")]
mod ffi;

#[cfg(feature = "ffi")]
use sawp_ffi::GenerateFFI;

pub const CRLF: &[u8] = b"\r\n";
pub const DATA_TYPE_TOKENS: &str = "$*+-:";
pub const MAX_ARRAY_DEPTH: usize = 64;
/// Bulk strings should not exceed 512 MB in length.
pub const MAX_BULK_STRING_LEN: usize = 1024 * 512;

/// Error flags raised while parsing RESP - to be used in the returned Message
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, BitFlags)]
pub enum ErrorFlags {
    /// Malformed data including invalid type tokens, invalid integers,
    /// or improperly formatted RESP has been parsed.
    InvalidData = 0b0000_0001,
    /// The length of a bulk string exceeds the specification-defined max 1024*512 bytes.
    /// SAWP will try to return the whole string.
    BulkStringExceedsMaxLen = 0b0000_0010,
    /// An array of arrays with > MAX_ARRAY_DEPTH depth was found. Message will truncate
    /// at the limit but futher bytes WILL NOT be consumed.
    MaxArrayDepthReached = 0b0000_0100,
}

/// RESP signals data types by prepending these one-character tokens
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum DataTypeToken {
    /// A single binary-safe string up to 512 MB in length. Precedes a CRLF-terminated length describing the following
    /// string. Can also be used to signal non-existence of a value using a special format that is used to represent a
    /// null value i.e. "$-1\r\n". Note the 'empty' string still CRLF-terminates unlike the null value
    /// i.e. "$0\r\n\r\n".
    BulkString = b'$',
    /// Clients send commands to the Redis server using RESP arrays. Servers can also return collections of elements
    /// with arrays. Precedes a CRLF-terminated length describing the following array. Empty type: "*0\r\n". Note
    /// that single elements to the array may be null, in which case the element will look like the null value as
    /// described in BulkString
    Array = b'*',
    /// Used to transmit non-binary-safe strings. These strings cannot contain '\r' or '\n' and are terminated by
    /// "\r\n".
    SimpleString = b'+',
    /// Exactly like simple strings but errors should be treated by the client as exceptions.
    Error = b'-',
    /// Like simple strings, but representing an integer.
    Integer = b':',
    Unknown,
}

impl DataTypeToken {
    pub fn from_raw(val: u8) -> Self {
        DataTypeToken::try_from(val).unwrap_or(DataTypeToken::Unknown)
    }
}

/// Entry types to return in the parsed message
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_resp"))]
#[derive(Debug, PartialEq, Eq)]
pub enum Entry {
    /// Arrays of entries
    Array(Vec<Entry>),
    /// The same as a String in practice but it may be useful to differentiate.
    Error(Vec<u8>),
    /// Integers
    Integer(i64),
    /// Invalid Data: a special type used here to return the data that would otherwise be lost after a recoverable parsing failure.
    /// This data will not be structured and is subject to interpretation.
    Invalid(Vec<u8>),
    /// The null value. Used to indicate a requested resource doesn't exist.
    /// Client libraries are supposed to return a "nil/null object" depending on the implementation language's preferred word.
    Nil,
    /// Simple Strings and Bulk Strings
    String(Vec<u8>),
}

pub enum IntegerResult<'a> {
    Integer(i64),
    Data(&'a [u8]),
}

pub enum StringResult<'a> {
    String(&'a [u8]),
    Nil,
    Invalid(&'a [u8], &'a [u8]), // length/data pair
}

/// Breakdown of the parsed resp bytes
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_resp"))]
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    pub entry: Entry,
    #[cfg_attr(feature = "ffi", sawp_ffi(flag = "u8"))]
    pub error_flags: Flags<ErrorFlags>,
}

impl Message {}

#[derive(Debug)]
pub struct Resp {}

impl<'a> Protocol<'a> for Resp {
    type Message = Message;

    fn name() -> &'static str {
        "resp"
    }
}

impl<'a> Probe<'a> for Resp {
    /// Probes the input to recognize if the underlying bytes likely match this
    /// protocol.
    ///
    /// Returns a probe status. Probe again once more data is available when the
    /// status is `Status::Incomplete`.
    fn probe(&self, input: &'a [u8], direction: Direction) -> Status {
        match self.parse(input, direction) {
            Ok((
                _,
                Some(Message {
                    entry: Entry::Invalid(_),
                    error_flags: _,
                }),
            )) => Status::Unrecognized, // If the only message is Invalid it is probably not RESP
            Ok(_) => Status::Recognized,
            Err(sawp::error::Error {
                kind: sawp::error::ErrorKind::Incomplete(_),
            }) => Status::Incomplete,
            Err(_) => Status::Unrecognized,
        }
    }
}

impl Resp {
    fn advance_if_crlf(input: &[u8]) -> &[u8] {
        crlf::<_, (&[u8], nom::error::ErrorKind)>(input)
            .map(|(rem, _)| rem)
            .unwrap_or(input)
    }

    fn parse_integer(input: &[u8]) -> Result<(&[u8], IntegerResult, Flags<ErrorFlags>)> {
        let (rem, raw_len) = take_until(CRLF)(input)?;
        // We don't know how long ret is but it is supposed to be valid text.
        match std::str::from_utf8(raw_len) {
            Ok(len_str) => match len_str.parse::<i64>() {
                Ok(len) => Ok((
                    Resp::advance_if_crlf(rem),
                    IntegerResult::Integer(len),
                    ErrorFlags::none(),
                )),
                Err(_) => Ok((
                    Resp::advance_if_crlf(rem),
                    IntegerResult::Data(raw_len),
                    ErrorFlags::InvalidData.into(),
                )),
            },
            Err(_) => Ok((
                Resp::advance_if_crlf(rem),
                IntegerResult::Data(raw_len),
                ErrorFlags::InvalidData.into(),
            )),
        }
    }

    /// The TypeOr looks a bit complicated but essentially means that if there are no errors we just return the parsed string data TypeOr::Left.
    /// If there is an error with the integer calculation we'll try to return the <integer data, string data> TyperOr::Right.
    /// Indicates a nil entry return for the caller via the returned bool
    fn parse_bulk_string(input: &[u8]) -> Result<(&[u8], StringResult, Flags<ErrorFlags>)> {
        let (rem, wrapped_length, mut error_flags) = Resp::parse_integer(input)?;
        match wrapped_length {
            IntegerResult::Integer(length) => {
                if length >= 0 {
                    if length > MAX_BULK_STRING_LEN as i64 {
                        error_flags |= ErrorFlags::BulkStringExceedsMaxLen
                    }
                    let (rem, ret) = take(length as usize)(rem)?;
                    // The standard states that even bulk strings should end with CRLF, but it may not be strictly necessary based on implementation?
                    Ok((
                        Resp::advance_if_crlf(rem),
                        StringResult::String(ret),
                        error_flags,
                    ))
                } else {
                    // Whether the result is the NULL string (-1 length) or some negative number, we can pass an "empty" result back with the inner error_flags and let the caller handle it.
                    if length == -1 {
                        return Ok((Resp::advance_if_crlf(rem), StringResult::Nil, error_flags));
                    }
                    error_flags |= ErrorFlags::InvalidData;
                    Ok((
                        Resp::advance_if_crlf(rem),
                        StringResult::String(b""),
                        error_flags,
                    ))
                }
            }
            IntegerResult::Data(bytes) => Ok((
                Resp::advance_if_crlf(rem),
                StringResult::Invalid(bytes, b""),
                error_flags,
            )),
        }
    }

    fn parse_simple_string(input: &[u8]) -> Result<(&[u8], &[u8])> {
        let (rem, ret) = take_until(CRLF)(input)?;
        // Remove the CRLF from remaining bytes
        Ok((Resp::advance_if_crlf(rem), ret))
    }

    fn parse_entry(input: &[u8], array_depth: usize) -> Result<(&[u8], Entry, Flags<ErrorFlags>)> {
        let (input, raw_token) = be_u8(input)?;
        let token = DataTypeToken::from_raw(raw_token);
        match token {
            DataTypeToken::BulkString => {
                let (rem, parsed_data, error_flags) = Resp::parse_bulk_string(input)?;
                match parsed_data {
                    StringResult::String(string_data) => {
                        Ok((rem, Entry::String(string_data.to_vec()), error_flags))
                    }
                    StringResult::Nil => Ok((rem, Entry::Nil, error_flags)),
                    StringResult::Invalid(len, data) => {
                        Ok((rem, Entry::Invalid([len, data].concat()), error_flags))
                    }
                }
            }
            DataTypeToken::Array => {
                if array_depth < MAX_ARRAY_DEPTH {
                    let (mut local_input, length, mut error_flags) = Resp::parse_integer(input)?;
                    match length {
                        IntegerResult::Integer(length) if length >= 0 => {
                            let mut entries: Vec<Entry> = Vec::with_capacity(length as usize);

                            for _ in 0..length {
                                let (rem, entry, inner_error_flags) =
                                    Resp::parse_entry(local_input, array_depth + 1)?;
                                error_flags |= inner_error_flags;
                                if error_flags.contains(ErrorFlags::MaxArrayDepthReached) {
                                    return Ok((input, Entry::Array(entries), error_flags));
                                }
                                entries.push(entry);
                                local_input = rem;
                            }
                            Ok((local_input, Entry::Array(entries), error_flags))
                        }
                        IntegerResult::Integer(-1) => Ok((local_input, Entry::Nil, error_flags)),
                        IntegerResult::Integer(_length) => {
                            error_flags |= ErrorFlags::InvalidData;
                            Ok((
                                Resp::advance_if_crlf(local_input),
                                Entry::Array(vec![]),
                                error_flags,
                            ))
                        }
                        IntegerResult::Data(invalid_length) => Ok((
                            Resp::advance_if_crlf(local_input),
                            Entry::Invalid(
                                [b"*", invalid_length].concat(), // include the token character in the returned value.
                            ),
                            error_flags,
                        )),
                    }
                } else {
                    Ok((
                        input,
                        Entry::Invalid(vec![]),
                        ErrorFlags::MaxArrayDepthReached.into(),
                    ))
                }
            }
            DataTypeToken::SimpleString => {
                let (rem, ret) = Resp::parse_simple_string(input)?;
                Ok((rem, Entry::String(ret.to_vec()), ErrorFlags::none()))
            }
            DataTypeToken::Error => {
                let (rem, ret) = Resp::parse_simple_string(input)?;
                Ok((
                    rem,
                    Entry::Error(ret.as_bytes().to_vec()),
                    ErrorFlags::none(),
                ))
            }
            DataTypeToken::Integer => {
                let (rem, ret, error_flags) = Resp::parse_integer(input)?;
                match ret {
                    IntegerResult::Integer(ret) => Ok((rem, Entry::Integer(ret), error_flags)),
                    IntegerResult::Data(ret) => Ok((
                        rem,
                        Entry::Invalid([b":", ret].concat()), // include the token character in the returned value.
                        error_flags,
                    )),
                }
            }
            DataTypeToken::Unknown => {
                // Advance to the next possible data type token, returning the "in-between" as InvalidData
                // Note we should include the first character in the returned value.
                let (rem, data) =
                    input.split_at_position_complete(|e: u8| DATA_TYPE_TOKENS.find_token(e))?;
                Ok((
                    Resp::advance_if_crlf(rem),
                    Entry::Invalid([&[raw_token], data].concat()),
                    ErrorFlags::InvalidData.into(),
                ))
            }
        }
    }
}

/// Returns ErrorKind::Incomplete if more data is needed.
/// If part of the message was parsed successfully will attempt to return a partial message
/// with an appropriate error_flags field indicating what went wrong.
impl<'a> Parse<'a> for Resp {
    fn parse(
        &self,
        input: &'a [u8],
        _direction: Direction,
    ) -> Result<(&'a [u8], Option<Self::Message>)> {
        let (rem, entry, error_flags) = Resp::parse_entry(input, 0)?;

        Ok((rem, Some(Message { entry, error_flags })))
    }
}

#[cfg(test)]
mod test {
    use crate::{Entry, ErrorFlags, Message, Resp};
    use rstest::rstest;
    use sawp::error::Result;
    use sawp::parser::{Direction, Parse};
    use sawp_flags::Flag;

    #[rstest(
    input,
    expected,
    case::parse_simple_string(
        b"+OK\r\n",
        Ok((
            0,
            Some(
                Message {
                    entry: Entry::String(b"OK".to_vec()),
                    error_flags: ErrorFlags::none(),
                }
            )
        ))
    ),
    case::parse_error(
        b"-Error message\r\n",
        Ok((
        0,
            Some(
                Message {
                    entry: Entry::Error(b"Error message".to_vec()),
                    error_flags: ErrorFlags::none(),
                }
            )
        ))
    ),
    case::parse_integer(
        b":1000\r\n",
        Ok((
            0,
            Some(
                Message {
                    entry: Entry::Integer(1000),
                    error_flags: ErrorFlags::none(),
                }
            )
        ))
    ),
    case::parse_bulk_string(
        b"$6\r\nfoobar\r\n",
        Ok((
            0,
            Some(
                Message {
                    entry: Entry::String(b"foobar".to_vec()),
                    error_flags: ErrorFlags::none(),
                }
            )
        ))
    ),
    case::parse_array(
        b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n",
        Ok((
            0,
            Some(
                Message {
                    entry: Entry::Array(vec!(
                        Entry::String(b"foo".to_vec()),
                        Entry::String(b"bar".to_vec()),
                    )),
                    error_flags: ErrorFlags::none(),
                }
            )
        ))
    ),
    case::parse_null_value_array(
        b"*-1\r\n",
        Ok((
            0,
            Some(
                Message {
                    entry: Entry::Nil,
                    error_flags: ErrorFlags::none(),
                }
            )
        ))
    ),
    case::invalid_negative_array_length(
        b"*-2\r\n",
        Ok((
            0,
            Some(
                Message {
                    entry: Entry::Array(vec![]),
                    error_flags: ErrorFlags::InvalidData.into(),
                }
            )
        ))
    ),
    case::parse_nested_array(
        b"*1\r\n*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n",
        Ok((
            0,
            Some(
                Message {
                    entry:
                        Entry::Array(vec!(
                            Entry::Array(vec!(
                                Entry::String(b"foo".to_vec()),
                                Entry::String(b"bar".to_vec()),
                            )),
                        ),
                    ),
                    error_flags: ErrorFlags::none(),
                }
            )
        ))
    ),
    case::parse_empty_array(
        b"*0\r\n",
        Ok((
            0,
            Some(
                Message {
                    entry: Entry::Array(vec![]),
                    error_flags: ErrorFlags::none(),
                }
            )
        ))
    ),
    case::nested_array_exceeds_max_depth(
    b"*2\r\n$3\r\nfoo\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n\
    *1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n\
    *1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n\
    *1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n\
    *1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n", // array depth 65
    Ok((
        268,
        Some(
            Message {
                entry:
                Entry::Array(vec![
                Entry::String(b"foo".to_vec()),
                ]),
                error_flags: ErrorFlags::MaxArrayDepthReached.into(),
            }
        )
    ))
    ),
    case::parse_empty_bulk_string_with_trailing_negative_int(
        b"*2\r\n$0\r\n\r\n:-100\r\n",
        Ok((
            0,
            Some(
                Message {
                    entry: Entry::Array(vec![
                        Entry::String(b"".to_vec()),
                        Entry::Integer(-100),
                    ]
                ),
                error_flags: ErrorFlags::none(),
                }
        )
        ))
    ),
    case::parse_null_value_string(
        b"$-1\r\n",
        Ok((
            0,
            Some(
                Message {
                    entry: Entry::Nil,
                    error_flags: ErrorFlags::none(),
                }
            )
        ))
    ),
    case::invalid_negative_bulk_string_length(
        b"$-2\r\n",
        Ok((
            0,
            Some(
                Message {
                    entry: Entry::String(b"".to_vec()),
                    error_flags: ErrorFlags::InvalidData.into(),
                }
            )
        ))
    ),
    case::invalid_type_token(
    b"!1\r\n",
    Ok((
        0,
        Some(
            Message {
                entry: Entry::Invalid(b"!1\r\n".to_vec()),
                error_flags: ErrorFlags::InvalidData.into(),
            }
        )
    ))
    ),
    case::invalid_type_token_mixed_with_good_data(
        b"!1\r\n$6\r\nfoobar\r\n",
        Ok((
            12,
            Some(
                Message {
                    entry: Entry::Invalid(b"!1\r\n".to_vec()),
                    error_flags: ErrorFlags::InvalidData.into(),
                }
            )
        ))
    ),
    case::missing_type_token(
        b"1\r\n$6\r\nfoobar\r\n",
        Ok((
            12,
            Some(
                Message {
                    entry: Entry::Invalid(b"1\r\n".to_vec()),
                    error_flags: ErrorFlags::InvalidData.into(),
                }
            )
        ))
    ),
    case::parse_too_big_integer(
        b":9223372036854775808\r\n", // int64 max + 1
        Ok((
            0,
            Some(
                Message {
                    entry: Entry::Invalid(b":9223372036854775808".to_vec()),
                    error_flags: ErrorFlags::InvalidData.into(),
                }
            )
        ))
    ),
    case::parse_too_small_integer(
        b":-9223372036854775809\r\n", // int64 min - 1
        Ok((
            0,
            Some(
                Message {
                    entry: Entry::Invalid(b":-9223372036854775809".to_vec()),
                    error_flags: ErrorFlags::InvalidData.into(),
                }
            )
        ))
    ),
    case::parse_invalid_integer(
    b":cats\r\n",
    Ok((
        0,
        Some(
            Message {
                entry: Entry::Invalid(b":cats".to_vec()),
                error_flags: ErrorFlags::InvalidData.into(),
            }
        )
    ))
    ),
    )]
    fn resp(input: &[u8], expected: Result<(usize, Option<Message>)>) {
        let resp = Resp {};
        assert_eq!(
            resp.parse(input, Direction::Unknown)
                .map(|(rem, msg)| (rem.len(), msg)),
            expected
        );
    }
}
