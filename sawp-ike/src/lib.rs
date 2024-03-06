//! An Internet Key Exchange (IKE) v1 and v2 parser.
//!
//! Given bytes and a [`sawp::parser::Direction`], it will attempt to parse the bytes
//! and return a [`Message`]. The parser will inform the caller about errors if no
//! message is returned and warnings if it was parsed but had nonstandard or erroneous
//! data (see [`sawp::parser::Parse`] for details on possible return types).
//!
//! This parser keeps state for the current session so it is expected to create one
//! parser per session.
//!
//! The following references were used to create this module:
//!
//! [ISAKMP](https://www.rfc-editor.org/rfc/rfc2408.html)
//!
//! [IKE v1](https://www.rfc-editor.org/rfc/rfc2409.html)
//!
//! [IKE v2 Fibre Channel](https://www.rfc-editor.org/rfc/rfc4595.html)
//!
//! [IKE v2](https://www.rfc-editor.org/rfc/rfc7296.html)
//!
//! [Group Key Management using IKEv2](https://datatracker.ietf.org/doc/draft-yeung-g-ikev2)
//!
//! # Example
//! ```
//! use sawp::parser::{Direction, Parse};
//! use sawp::error::Error;
//! use sawp::error::ErrorKind;
//! use sawp_ike::{Ike, Message};
//!
//! fn parse_bytes(input: &[u8]) -> std::result::Result<&[u8], Error> {
//!     let ike = Ike::default();
//!     let mut bytes = input;
//!     while bytes.len() > 0 {
//!         // If we know that this is a request or response, change the Direction
//!         // for a more accurate parsing
//!         match ike.parse(bytes, Direction::Unknown) {
//!             // The parser succeeded and returned the remaining bytes and the parsed ike message
//!             Ok((rest, Some(message))) => {
//!                 println!("IKE message: {:?}", message);
//!                 bytes = rest;
//!             }
//!             // The parser recognized that this might be ike and made some progress,
//!             // but more bytes are needed to parse a full message
//!             Ok((rest, None)) => return Ok(rest),
//!             // The parser was unable to determine whether this was ike or not and more
//!             // bytes are needed
//!             Err(Error { kind: ErrorKind::Incomplete(_) }) => return Ok(bytes),
//!             // The parser determined that this was not ike
//!             Err(e) => return Err(e)
//!         }
//!     }
//!
//!     Ok(bytes)
//! }
//! ```

#![deny(clippy::integer_arithmetic)]

pub mod header;
pub mod payloads;

use header::{Header, IkeFlags, HEADER_LEN};
use payloads::{Payload, PayloadType};

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

use nom::bytes::streaming::{tag, take};
use nom::combinator::opt;
use nom::number::streaming::be_u32;
use nom::sequence::tuple;

type IResult<'a, O> = nom::IResult<&'a [u8], O, sawp::error::NomError<&'a [u8]>>;

/// Classes of errors that can be returned by this parser.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, BitFlags)]
pub enum ErrorFlags {
    /// Unknown Exchange number
    UnknownExchange = 0b0000_0000_0000_0001,
    /// Unknown Payload number
    UnknownPayload = 0b0000_0000_0000_0010,
    /// Found a payload in an invalid location
    InvalidPayload = 0b0000_0000_0000_0100,
    /// Known payload found which we have no parser for
    UnimplementedPayload = 0b0000_0000_0000_1000,
    /// Message ID was nonzero in an initiation message
    NonZeroMessageIdInInit = 0b0000_0000_0001_0000,
    /// Responder SPI was nonzero in an initiation message
    NonZeroResponderSpiInInit = 0b0000_0000_0010_0000,
    /// Responder SPI was not set in a response message
    ZeroResponderSpiInResponse = 0b0000_0000_0100_0000,
    /// Non-Zero reserved field found
    NonZeroReserved = 0b0000_0000_1000_0000,
    /// Invalid length in a payload
    ///
    /// Typically indicative of a length which is too short to accomodate the generic payload
    /// header
    InvalidLength = 0b0000_0001_0000_0000,
    /// Header flags were invalid.
    ///
    /// Either a nonexistant flag bit was set or both IKEv1 and IKEv2 flags were set at the same
    /// time.
    InvalidFlags = 0b0000_0010_0000_0000,
}

impl ErrorFlags {
    fn flatten(input: &[Flags<Self, u16>]) -> Flags<Self, u16> {
        input.iter().fold(Self::none(), |acc, e| acc | *e)
    }
}

/// The parsed message.
///
/// [`Message::Ike`] is a parsed IKE v1 or v2 message.
///
/// [`Message::Esp`] is an encapsulated security payload. These are seen when the
/// encrypted communications are sent over UDP on the same 5-tuple as the IKE messages, typically on port 4500.
/// When IKE operates over TCP, no ESP will be parsed as they encrypted data is sent without a
/// transport layer (i.e. layer 3 Ethernet header followed by encrypted payload).
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    /// An IKE payload
    Ike(IkeMessage),
    /// Encapsulating Security Payload
    Esp(EspMessage),
}

/// The parsed IKEv1 or v2 message
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct IkeMessage {
    /// The header
    pub header: Header,
    /// The array of payloads following the header
    pub payloads: Vec<Payload>,
    /// Encrypted Data, if IKEv1 and ENCRYPTED flag is set
    pub encrypted_data: Vec<u8>,
    /// Errors encountered while parsing
    #[cfg_attr(feature = "ffi", sawp_ffi(flag = "u16"))]
    pub error_flags: Flags<ErrorFlags>,
}

/// If UDP encapsulation is present, the metadata associated with it is parsed.
///
/// The full encrypted payload, tail padding, and integrity check is not parsed.
#[cfg_attr(feature = "ffi", derive(GenerateFFI))]
#[cfg_attr(feature = "ffi", sawp_ffi(prefix = "sawp_ike"))]
#[derive(Debug, PartialEq, Eq)]
pub struct EspMessage {
    pub spi: u32,
    pub sequence: u32,
}

/// Parser handle.
///
/// # Notes
/// The parser assumes one parser per session as it stores session state. A given session should
/// re-use the same parser as more data is made available and each session should have its own
/// parser.
///
/// # FFI SAFETY
/// This type is not [`Sync`] and this must be considered in FFI uses. This struct may be sent from
/// one thread to another but it may not be shared between threads without locking access. In C++
/// this means a std::shared_ptr<Ike> is not enough! std::mutex or other locking primitives must be
/// used to ensure data races do not occur.
#[derive(Debug, Default)]
pub struct Ike {
    // On port 4500 ESP payloads are encapsulated in UDP but on port 500 they are not.
    // When UDP encapsulation for ESP is present IKE payloads are prefixed with 4 octets
    // 0x00 to differentiate them from ESP.
    //
    // When an IKE payload was prefixed with 0x00 we should treat any seen packets without
    // it as ESP payloads. When IKE was not prefixed with 0x00 then all packets should
    // be IKE. As such we have 3 states - ESP encapsulation present (Some(true)), ESP
    // encapsulation not present (Some(false)), and not yet determined (None).
    saw_udp_encapsulation: std::cell::Cell<Option<bool>>,
}

impl Probe<'_> for Ike {}

impl Protocol<'_> for Ike {
    type Message = Message;

    fn name() -> &'static str {
        "ike"
    }
}

impl<'a> Parse<'a> for Ike {
    fn parse(
        &self,
        input: &'a [u8],
        _direction: Direction,
    ) -> Result<(&'a [u8], Option<Self::Message>)> {
        let input = match self.saw_udp_encapsulation.get() {
            // Previously saw encapsulation
            Some(true) => {
                let (input, non_esp_marker) = opt(tag(b"\x00\x00\x00\x00"))(input)?;
                if non_esp_marker.is_some() {
                    // marker present, must be IKE. Continue
                    input
                } else {
                    let (input, (spi, sequence)) = tuple((be_u32, be_u32))(input)?;
                    return Ok((input, Some(Message::Esp(EspMessage { spi, sequence }))));
                }
            }
            // Previously saw no encapsulation
            Some(false) => {
                // Parse like normal
                input
            }
            // Not yet determined
            None => {
                let (input, non_esp_marker) = opt(tag(b"\x00\x00\x00\x00"))(input)?;
                self.saw_udp_encapsulation
                    .set(Some(non_esp_marker.is_some()));
                input
            }
        };

        let (input, (header, header_error_flags)) = Header::parse(input)?;

        // subtracting HEADER_LEN is safe, length verified in Header::parse
        let (input, mut payload_input) = take(header.length.saturating_sub(HEADER_LEN))(input)?;

        let mut next_payload = header.next_payload;
        let mut payloads = Vec::new();
        let mut payload_error_flags = ErrorFlags::none();

        if header.major_version == 1 && header.flags.contains(IkeFlags::ENCRYPTED) {
            let message = Message::Ike(IkeMessage {
                header,
                payloads: Vec::new(),
                encrypted_data: payload_input.to_vec(),
                error_flags: ErrorFlags::none(),
            });
            return Ok((input, Some(message)));
        }

        let parse = if header.major_version == 1 {
            Payload::parse_v1
        } else {
            Payload::parse_v2
        };

        // While we have a next payload and they are not encrypted
        // In the case of encryption, all the payloads are encrypted and
        // are inside the encrypted data block.
        while next_payload != PayloadType::NoNextPayload {
            let should_early_break = next_payload == PayloadType::EncryptedAndAuthenticated
                || next_payload == PayloadType::EncryptedAndAuthenticatedFragment;
            let (tmp_payload_input, (payload, errors)) = parse(payload_input, next_payload)?;
            // We need _payload_input as an interim variable until de structuring assignments are
            // supported in our MSRV rust version
            payload_input = tmp_payload_input;
            next_payload = payload.next_payload;
            payloads.push(payload);
            payload_error_flags |= errors;

            if should_early_break {
                break;
            }
        }

        let error_flags = header_error_flags | payload_error_flags;

        let message = Message::Ike(IkeMessage {
            header,
            payloads,
            encrypted_data: Vec::with_capacity(0),
            error_flags,
        });

        Ok((input, Some(message)))
    }
}
