//! A Generic Routing Encapsulation (GRE) protocol parser. Given bytes and a
//! [`sawp::parser::Direction`], it will attempt to parse the bytes and return a [`Message`]. The
//! parser will inform the caller about what went wrong if no message is returned (see
//! [`sawp::parser::Parse`] for details on possible return types).
//!
//! The following protocol references were used to create this module:
//!
//! [CURRENT GRE RFC2784] https://tools.ietf.org/html/rfc2784
//! [DEPRECATED GRE RFC1701] https://tools.ietf.org/html/rfc1701
//! [POINT TO POINT TUNNELING RFC2637] https://tools.ietf.org/html/rfc2637
//!
//! # Example
//! ```
//! use sawp::parser::{Direction, Parse};
//! use sawp::error::Error;
//! use sawp::error::ErrorKind;
//! use sawp_gre::{Gre, Message};
//!
//! fn parse_bytes(input: &[u8]) -> std::result::Result<&[u8], Error> {
//!     let gre = Gre {};
//!     let mut bytes = input;
//!     while bytes.len() > 0 {
//!         match gre.parse(bytes, Direction::Unknown) {
//!             // The parser succeeded and returned the remaining bytes and the parsed gre message.
//!             Ok((rest, Some(message))) => {
//!                 println!("Gre message: {:?}", message);
//!                 bytes = rest;
//!             }
//!             // The parser recognized that this might be gre and made some progress,
//!             // but more bytes are needed.
//!             Ok((rest, None)) => return Ok(rest),
//!             // The parser was unable to determine whether this was gre or not and more bytes are
//!             // needed.
//!             Err(Error { kind: ErrorKind::Incomplete(_) }) => return Ok(bytes),
//!             // The parser determined that this was not gre
//!             Err(e) => return Err(e)
//!         }
//!     }
//!
//!     Ok(bytes)
//! }
//! ````

use sawp::error::{Error, ErrorKind, Result};
use sawp::parser::{Direction, Parse};
use sawp::probe::{Probe, Status};
use sawp::protocol::Protocol;

use sawp_flags::BitFlags;
pub use sawp_flags::{Flag, Flags};

use nom::bytes::streaming::take;
use nom::number::streaming::{be_u16, be_u32, be_u8};

use std::ops::BitAnd;

/// Upper limit on number of Source Route Entries to be handled when routing bit is set in deprecated
/// GRE to avoid an infinite loop.
const MAX_SRE_ENTRIES: u32 = 10;
/// Required protocol type for PPP. Beyond checking for this protocol type, the GRE parser is not
/// concerned about the protocol type.
const ETHERTYPE_PPP: u16 = 0x880b;

/// Flags which identify messages which parse as Gre
/// but contain invalid data. The caller can use the message's
/// error flags to see if and what errors were in the
/// pack of bytes and take action using this information.
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, BitFlags)]
pub enum ErrorFlags {
    /// Indicate that a reserve bit in the gre_flags field is inappropriately set
    RESERVE = 0b0000_0001,
    /// Indicate that a reserve bit in the version field (including an incorrect version)
    /// is inappropriately set
    VERSION = 0b0000_0010,
    /// Indicate that a reserve bit in the reserve1 field is inappropriately set. This is only a
    /// concern with the current version of GRE (RFC 2874)
    RESERVE1 = 0b0000_0100,
    /// Indicate that the maximum number of source route entries has been processed. This means that
    /// there is more data remaining than what was processed into the message.
    MAX_SRE_REACHED = 0b0000_1000,
}

/// Flags for handling the first 2 octets of data containing GRE flags (and PPTP specific flags)
///    0                   1
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |C|R|K|S|s|Recur|A| Flags | Ver |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, BitFlags)]
#[repr(u16)]
pub enum GreFlags {
    CHECKSUM = 0b1000_0000_0000_0000,
    ROUTING = 0b0100_0000_0000_0000,
    KEY = 0b0010_0000_0000_0000,
    SEQUENCE_NUMBER = 0b0001_0000_0000_0000,
    STRICT_SOURCE_ROUTE = 0b0000_1000_0000_0000,
    RECURSION = 0b0000_0111_0000_0000,
    ACKNOWLEDGEMENT = 0b0000_0000_1000_0000,
    FLAGS = 0b0000_0000_0111_1000,
    VERSION = 0b0000_0000_0000_0111,
    RESERVED_GRE = 0b0111_1111_1111_1111,
    RESERVED_DEPRECATED_GRE = 0b0000_0111_1111_1111,
    RESERVED_PPTP = 0b1100_1111_0111_1110,
    RESERVED_FLAGS = 0b0000_0111_0111_1000,
    VERSION_GRE = 0b0000_0000_0000_0000,
    VERSION_PPTP = 0b0000_0000_0000_0001,
}

/// Source Route Entries are present in deprecated GRE and need to be handled.
/// See https://tools.ietf.org/html/rfc1701 for implementation in GRE headers
/// and https://tools.ietf.org/html/rfc1702 for further details.
#[derive(Debug, PartialEq, Eq)]
pub struct SourceRouteEntry {
    address_family: u16,
    sre_offset: u8,
    sre_length: u8,
    routing_info: Vec<u8>,
}

/// Enum for handling the different GRE headers supported.
/// GRE Versions supported:
///  Current GRE: https://tools.ietf.org/html/rfc2784
///  Deprecated GRE: https://tools.ietf.org/html/rfc1701
///  Point-to-Point Tunneling Protocol (Enhanced GRE Header): https://tools.ietf.org/html/rfc2637
#[derive(Debug, PartialEq, Eq)]
pub enum Data {
    Gre {
        checksum: Option<u16>,
        reserved: Option<u16>,
    },
    GreDeprecated {
        checksum: Option<u16>,
        offset: Option<u16>,
        key: Option<u32>,
        sequence_number: Option<u32>,
        source_route_entries: Vec<SourceRouteEntry>,
    },
    Pptp {
        payload_length: u16,
        call_id: u16,
        sequence_number: Option<u32>,
        acknowledgement_number: Option<u32>,
        payload: Vec<u8>,
    },
    Empty,
}

#[derive(Debug)]
pub struct Gre {}

/// Breakdown of the parsed GRE bytes
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    pub header: Flags<GreFlags>,
    pub protocol_type: u16,
    pub data: Data,
    pub error_flags: Flags<ErrorFlags>,
}

impl Message {
    /// Convenience functions for handling the various components of the flag/version bits in a
    /// GRE header.

    fn is_checksum_set(&self) -> bool {
        self.header.intersects(GreFlags::CHECKSUM)
    }

    fn is_routing_set(&self) -> bool {
        self.header.intersects(GreFlags::ROUTING)
    }

    fn is_key_set(&self) -> bool {
        self.header.intersects(GreFlags::KEY)
    }

    fn is_sequence_number_set(&self) -> bool {
        self.header.intersects(GreFlags::SEQUENCE_NUMBER)
    }

    fn is_acknowledgement_set(&self) -> bool {
        self.header.intersects(GreFlags::ACKNOWLEDGEMENT)
    }

    fn version(&self) -> Flags<GreFlags> {
        self.header.bitand(GreFlags::VERSION)
    }

    fn is_reserved_gre_set(&self) -> bool {
        self.header.intersects(GreFlags::RESERVED_GRE)
    }

    fn is_reserved_deprecated_gre_set(&self) -> bool {
        self.header.intersects(GreFlags::RESERVED_DEPRECATED_GRE)
    }

    fn is_reserved_pptp_set(&self) -> bool {
        self.header.intersects(GreFlags::RESERVED_PPTP)
    }

    fn is_reserved_flags_set(&self) -> bool {
        self.header.intersects(GreFlags::RESERVED_FLAGS)
    }

    fn is_valid_gre(&self) -> bool {
        !self.is_reserved_gre_set()
    }

    fn is_valid_deprecated_gre(&self) -> bool {
        !self.is_reserved_deprecated_gre_set()
    }

    fn is_valid_pptp(&self) -> bool {
        !self.is_reserved_pptp_set()
            && self.is_key_set()
            && self.version().contains(GreFlags::VERSION_PPTP)
            && self.protocol_type == ETHERTYPE_PPP
    }

    /// Used for GRE and Deprecated GRE. If checksum or routing bit is set grab the checksum and
    /// reserve bytes. If not, return input and Nones for checksum and offset immediately.
    fn parse_checksum_and_routing<'a>(
        &mut self,
        input: &'a [u8],
    ) -> Result<(&'a [u8], Option<u16>, Option<u16>)> {
        if self.is_checksum_set() || self.is_routing_set() {
            let (input, checksum) = be_u16(input)?;
            let (input, offset) = be_u16(input)?;
            Ok((input, Some(checksum), Some(offset)))
        } else {
            Ok((input, None, None))
        }
    }

    /// Used for deprecated GRE. If the key bit is set, grab the key bytes. If not, return input and
    /// None immediately. Note: While PPTP does have the key bit set, it's bytes have a different
    /// meaning (2 bytes for a payload length field and 2 bytes for a call id field) and thus need
    /// to be handled differently.
    fn parse_key<'a>(&mut self, input: &'a [u8]) -> Result<(&'a [u8], Option<u32>)> {
        if self.is_key_set() {
            let (input, key) = be_u32(input)?;
            Ok((input, Some(key)))
        } else {
            Ok((input, None))
        }
    }

    /// Used for deprecated GRE and PPTP. If the sequence bit is set, grab the sequence bytes. If
    /// not, return input and None immediately.
    fn parse_sequence<'a>(&mut self, input: &'a [u8]) -> Result<(&'a [u8], Option<u32>)> {
        if self.is_sequence_number_set() {
            let (input, sequence) = be_u32(input)?;
            Ok((input, Some(sequence)))
        } else {
            Ok((input, None))
        }
    }

    /// Used for PPTP. If acknowledgement bit set, grab the acknowledgement bytes. If
    /// not, return input and None for acknowledgement immediately.
    fn parse_acknowledgement<'a>(&mut self, input: &'a [u8]) -> Result<(&'a [u8], Option<u32>)> {
        if self.is_acknowledgement_set() {
            let (input, acknowledgement) = be_u32(input)?;
            Ok((input, Some(acknowledgement)))
        } else {
            Ok((input, None))
        }
    }

    /// Used for deprecated GRE. If the routing bit is set, process the source route entries
    /// contained in the GRE header. This loops through the input until a source route entry with
    /// address_family 0x0000 and sre_length 0x00 is reached OR until a maximum number of SRE
    /// entries are processed to avoid infinite looping. An error flag will be set if the maximum
    /// number of SRE entries are reached to indicate that there may have been bytes not processed.
    fn parse_source_route_entries<'a>(
        &mut self,
        input: &'a [u8],
    ) -> Result<(&'a [u8], Vec<SourceRouteEntry>)> {
        if self.is_routing_set() {
            let mut source_route_entries: Vec<SourceRouteEntry> = Vec::new();
            let mut input_copy = input;
            for _ in 0..MAX_SRE_ENTRIES {
                let (input, address_family) = be_u16(input_copy)?;
                let (input, sre_offset) = be_u8(input)?;
                let (input, sre_length) = be_u8(input)?;
                let (input, routing_raw) = take(sre_length)(input)?;
                let source_route_entry = SourceRouteEntry {
                    address_family,
                    sre_offset,
                    sre_length,
                    routing_info: routing_raw.to_vec(),
                };
                source_route_entries.push(source_route_entry);
                if address_family == 0 && sre_length == 0 {
                    return Ok((input, source_route_entries));
                }
                input_copy = input;
            }
            self.error_flags |= ErrorFlags::MAX_SRE_REACHED;
            Ok((input_copy, source_route_entries))
        } else {
            Ok((input, vec![]))
        }
    }

    /// Used for PPTP. If sequence bit is set in PPTP, grab the payload based on the previously
    /// parsed payload length. If not, return input and an empty vector for Payload immediately.
    fn parse_pptp_payload<'a>(
        &mut self,
        input: &'a [u8],
        length: u16,
    ) -> Result<(&'a [u8], Vec<u8>)> {
        if self.is_sequence_number_set() {
            let (input, payload) = take(length)(input)?;
            Ok((input, payload.to_vec()))
        } else {
            Ok((input, vec![]))
        }
    }

    /// Main parsing function for current GRE. Only additional fields to be handled are the checksum
    /// and reserve1. Checks validity of reserve1 and adds error flag if it is not zero.
    fn parse_gre<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        let (input, checksum, reserved) = self.parse_checksum_and_routing(input)?;
        self.data = Data::Gre { checksum, reserved };

        if let Some(reserved) = reserved {
            if reserved > 0 {
                self.error_flags |= ErrorFlags::RESERVE1;
            }
        }
        Ok(input)
    }

    /// Main parsing function for deprecated GRE. There are no validity checks that need to be done
    /// on the content of these fields.
    fn parse_deprecated<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        let (input, checksum, offset) = self.parse_checksum_and_routing(input)?;
        let (input, key) = self.parse_key(input)?;
        let (input, sequence_number) = self.parse_sequence(input)?;
        let (input, source_route_entries) = self.parse_source_route_entries(input)?;

        self.data = Data::GreDeprecated {
            checksum,
            offset,
            key,
            sequence_number,
            source_route_entries,
        };

        Ok(input)
    }

    /// Main parsing function for PPTP. There are no validity checks that need to be done on the
    /// content of these fields.
    fn parse_pptp<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8]> {
        let (input, payload_length) = be_u16(input)?;
        let (input, call_id) = be_u16(input)?;
        let (input, sequence_number) = self.parse_sequence(input)?;
        let (input, acknowledgement_number) = self.parse_acknowledgement(input)?;
        let (input, payload) = self.parse_pptp_payload(input, payload_length)?;
        self.data = Data::Pptp {
            payload_length,
            call_id,
            sequence_number,
            acknowledgement_number,
            payload,
        };

        Ok(input)
    }

    /// Takes a look at the flag/version bits and determines whether or not some reserved bits are set.
    /// The error set is just a generic reserve flag, i.e. doesn't specify whether or not this
    /// reserve is violated in recur bits or somewhere else (depending on version of GRE). The bits
    /// checked are the reserved bits shared by all the supported gre implementations.
    fn check_error_gre_flags(&mut self) {
        if self.is_reserved_flags_set() {
            self.error_flags |= ErrorFlags::RESERVE;
        }
    }

    /// Takes a look at the version bits to determine whether or not the reason for not recognizing
    /// the input as gre was due to an unsupported version type.
    fn check_error_version_flags(&mut self) {
        if self.version() != GreFlags::VERSION_PPTP && self.version() != GreFlags::VERSION_GRE {
            self.error_flags |= ErrorFlags::VERSION;
        }
    }
}

impl Protocol<'_> for Gre {
    type Message = Message;

    fn name() -> &'static str {
        "gre"
    }
}

impl<'a> Probe<'a> for Gre {
    fn probe(&self, input: &'a [u8], direction: Direction) -> Status {
        match self.parse(input, direction) {
            Ok((_, Some(msg))) => {
                if msg.error_flags == ErrorFlags::none() {
                    Status::Recognized
                } else {
                    Status::Unrecognized
                }
            }
            Ok((_, _)) => Status::Recognized,
            Err(Error {
                kind: ErrorKind::Incomplete(_),
            }) => Status::Incomplete,
            Err(_) => Status::Unrecognized,
        }
    }
}

impl<'a> Parse<'a> for Gre {
    fn parse(
        &self,
        input: &'a [u8],
        _direction: Direction,
    ) -> Result<(&'a [u8], Option<Self::Message>)> {
        let (input, gre_flags_raw) = be_u16(input)?;
        let (input, protocol_type) = be_u16(input)?;

        let mut message = Message {
            header: Flags::from_bits(gre_flags_raw),
            protocol_type,
            data: Data::Empty,
            error_flags: ErrorFlags::none(),
        };

        if message.is_valid_gre() {
            let input = message.parse_gre(input)?;
            Ok((input, Some(message)))
        } else if message.is_valid_deprecated_gre() {
            let input = message.parse_deprecated(input)?;
            Ok((input, Some(message)))
        } else if message.is_valid_pptp() {
            let input = message.parse_pptp(input)?;
            Ok((input, Some(message)))
        } else {
            message.check_error_gre_flags();
            message.check_error_version_flags();
            Ok((input, Some(message)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use sawp::probe::Status;

    #[test]
    fn test_name() {
        assert_eq!(Gre::name(), "gre");
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Err(Error::incomplete_needed(2))),
        case::basic_ip(
            &[
                // header: No flags set. Version zero.
                0x00, 0x00,
                // protocol type (ip)
                0x08, 0x00,
            ],
            Ok((&[] as &[u8], Some(Message{
                header: GreFlags::none(),
                protocol_type: 0x0800,
                data: Data::Gre {
                    checksum: None,
                    reserved: None,
                },
                error_flags: ErrorFlags::none(),
            })))),
        case::checksum(
            &[
                // header: Checksum flag set. Version zero.
                0x80, 0x00,
                // protocol type IPV6
                0x86, 0xdd,
                // checksum bytes
                0xab, 0xcd,
                // reserved1: zero
                0x00, 0x00,
            ],
            Ok((&[] as &[u8], Some(Message{
                header: GreFlags::CHECKSUM.into(),
                protocol_type: 0x86dd,
                data: Data::Gre {
                    checksum: Some(43981),
                    reserved: Some(0),
                },
                error_flags: ErrorFlags::none(),
            })))),
        case::checksum_missing(
            &[
                // header: Checksum flag set. Version zero.
                0x80, 0x00,
                // protocol type IPV6
                0x86, 0xdd,
            ],
            Err(Error::incomplete_needed(2))),
        case::error_reserve(
            &[
                // header: No checksum and non zero reserves. Version zero.
                0x7a, 0x00,
                // protocol type (ip)
                0x08, 0x00,
            ],
            Ok((&[] as &[u8], Some(Message{
                header: Flags::from_bits(31232),
                protocol_type: 0x0800,
                data: Data::Empty,
                error_flags: ErrorFlags::RESERVE.into(),
            })))),
        case::error_version(
            &[
                // header: No flags set. Invalid version (2).
                0x00, 0x02,
                // protocol type (ip)
                0x88, 0xbe,
            ],
                Ok((&[] as &[u8], Some(Message{
                    header: Flags::from_bits(2),
                    protocol_type: 0x88be,
                    data: Data::Empty,
                    error_flags: ErrorFlags::VERSION.into(),
            })))),
        case::error_reserve1(
            &[
                // header: checksum set. Version zero.
                0x80, 0x00,
                // protocol type (IPV6)
                0x86, 0xdd,
                // checksum bytes
                0xab, 0xcd,
                // reserved1 bytes. Non zero.
                0x00, 0x40,
            ],
            Ok((&[] as &[u8], Some(Message{
                header: GreFlags::CHECKSUM.into(),
                protocol_type: 0x86dd,
                data: Data::Gre {
                    checksum: Some(43981),
                    reserved: Some(64),
                },
                error_flags: ErrorFlags::RESERVE1.into(),
            })))),
        case::deprecated_routing_no_sre(
            &[
                // header: routing flag set. Version zero.
                0x40, 0x00,
                // protocol type: ip
                0x08, 0x00,
                // checksum
                0x00, 0x43,
                // offset
                0x00, 0x21,
                // routing: empty
                0x00, 0x00, 0x00, 0x00,
            ],
            Ok((&[] as &[u8], Some(Message{
                header: GreFlags::ROUTING.into(),
                protocol_type: 0x0800,
                data: Data::GreDeprecated {
                    checksum: Some(67),
                    offset: Some(33),
                    key: None,
                    sequence_number: None,
                    source_route_entries: vec![SourceRouteEntry {
                        address_family: 0,
                        sre_offset: 0,
                        sre_length: 0,
                        routing_info: vec![],
                    }],
                },
                error_flags: ErrorFlags::none(),
            })))),
        case::deprecated_routing_sre(
                &[
                    // header: checksum and routing flags set. Version 0.
                    0xc0, 0x00,
                    // protocol type: ip
                    0x08, 0x00,
                    // checksum
                    0x00, 0x43,
                    // offset
                    0x00, 0x21,
                    // routing entry 1
                    0x12, 0x34, 0x56, 0x04,
                    // payload
                    0xff, 0xff, 0xff, 0xff,
                    // routing entry 2
                    0xab, 0xcd, 0xef, 0x08,
                    0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff,
                    // last routing entry
                    0x00, 0x00, 0x00, 0x00,
                ],
                Ok((&[] as &[u8], Some(Message{
                    header: GreFlags::CHECKSUM | GreFlags::ROUTING,
                    protocol_type: 0x0800,
                    data: Data::GreDeprecated {
                        checksum: Some(67),
                        offset: Some(33),
                        key: None,
                        sequence_number: None,
                        source_route_entries: vec![SourceRouteEntry {
                            address_family: 4660,
                            sre_offset: 86,
                            sre_length: 4,
                            routing_info: vec![0xff, 0xff, 0xff, 0xff],
                        }, SourceRouteEntry {
                            address_family: 43981,
                            sre_offset: 239,
                            sre_length: 8,
                            routing_info: vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                        }, SourceRouteEntry {
                            address_family: 0,
                            sre_offset: 0,
                            sre_length: 0,
                            routing_info: vec![],
                        }],
                    },
                    error_flags: ErrorFlags::none(),
                })))),
        case::deprecated_routing_max_sre(
            &[
                // header: checksum and routing flags set. Version 0.
                0xc0, 0x00,
                // protocol type: ip
                0x08, 0x00,
                // checksum
                0x00, 0x43,
                // offset
                0x00, 0x21,
                // routing entry 1
                0x12, 0x34, 0x56, 0x04,
                // payload
                0xff, 0xff, 0xff, 0xff,
                // routing entry 2
                0x12, 0x34, 0x56, 0x04,
                // payload
                0xff, 0xff, 0xff, 0xff,
                // routing entry 3
                0x12, 0x34, 0x56, 0x04,
                // payload
                0xff, 0xff, 0xff, 0xff,
                // routing entry 4
                0x12, 0x34, 0x56, 0x04,
                // payload
                0xff, 0xff, 0xff, 0xff,
                // routing entry 5
                0x12, 0x34, 0x56, 0x04,
                // payload
                0xff, 0xff, 0xff, 0xff,
                // routing entry 6
                0x12, 0x34, 0x56, 0x04,
                // payload
                0xff, 0xff, 0xff, 0xff,
                // routing entry 7
                0x12, 0x34, 0x56, 0x04,
                // payload
                0xff, 0xff, 0xff, 0xff,
                // routing entry 8
                0x12, 0x34, 0x56, 0x04,
                // payload
                0xff, 0xff, 0xff, 0xff,
                // routing entry 9
                0x12, 0x34, 0x56, 0x04,
                // payload
                0xff, 0xff, 0xff, 0xff,
                // routing entry 10 (MAX_SRE_ENTRIES)
                0x12, 0x34, 0x56, 0x04,
                // payload
                0xff, 0xff, 0xff, 0xff,
            ],
            Ok((&[] as &[u8], Some(Message{
                header: GreFlags::CHECKSUM | GreFlags::ROUTING,
                protocol_type: 0x0800,
                data: Data::GreDeprecated {
                checksum: Some(67),
                offset: Some(33),
                key: None,
                sequence_number: None,
                source_route_entries: vec![SourceRouteEntry {
                    address_family: 4660,
                    sre_offset: 86,
                    sre_length: 4,
                    routing_info: vec![0xff, 0xff, 0xff, 0xff],
                }, SourceRouteEntry {
                    address_family: 4660,
                    sre_offset: 86,
                    sre_length: 4,
                    routing_info: vec![0xff, 0xff, 0xff, 0xff],
                }, SourceRouteEntry {
                    address_family: 4660,
                    sre_offset: 86,
                    sre_length: 4,
                    routing_info: vec![0xff, 0xff, 0xff, 0xff],
                }, SourceRouteEntry {
                    address_family: 4660,
                    sre_offset: 86,
                    sre_length: 4,
                    routing_info: vec![0xff, 0xff, 0xff, 0xff],
                }, SourceRouteEntry {
                    address_family: 4660,
                    sre_offset: 86,
                    sre_length: 4,
                    routing_info: vec![0xff, 0xff, 0xff, 0xff],
                }, SourceRouteEntry {
                    address_family: 4660,
                    sre_offset: 86,
                    sre_length: 4,
                    routing_info: vec![0xff, 0xff, 0xff, 0xff],
                }, SourceRouteEntry {
                    address_family: 4660,
                    sre_offset: 86,
                    sre_length: 4,
                    routing_info: vec![0xff, 0xff, 0xff, 0xff],
                }, SourceRouteEntry {
                    address_family: 4660,
                    sre_offset: 86,
                    sre_length: 4,
                    routing_info: vec![0xff, 0xff, 0xff, 0xff],
                }, SourceRouteEntry {
                    address_family: 4660,
                    sre_offset: 86,
                    sre_length: 4,
                    routing_info: vec![0xff, 0xff, 0xff, 0xff],
                }, SourceRouteEntry {
                    address_family: 4660,
                    sre_offset: 86,
                    sre_length: 4,
                    routing_info: vec![0xff, 0xff, 0xff, 0xff],
                }],
                },
                error_flags: ErrorFlags::MAX_SRE_REACHED.into(),
            })))),
        case::deprecated_routing_sre_missing(
            &[
                // header: checksum and routing flags set. Version 0.
                0xc0, 0x00,
                // protocol type: ip
                0x08, 0x00,
                // checksum
                0x00, 0x43,
                // offset
                0x00, 0x21,
                // routing entry 1
                0x12, 0x34, 0x56, 0x04,
                // payload
                0xff, 0xff, 0xff, 0xff,
                // routing entry 2
                0xab, 0xcd, 0xef, 0x08,
                0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
                // last routing entry missing (needs 0x0000__00 to signal last SRE)
            ],
            Err(Error::incomplete_needed(2))),
        case::deprecated_key(
            &[
                // gre_flags: key set
                0x20,
                // version: must be zero
                0x00,
                // protocol type: ip
                0x08, 0x00,
                // key
                0x12, 0x34, 0x56, 0x78,
            ],
            Ok((&[] as &[u8], Some(Message {
                header: GreFlags::KEY.into(),
                protocol_type: 0x0800,
                data: Data::GreDeprecated {
                    checksum: None,
                    offset: None,
                    key: Some(305_419_896),
                    sequence_number: None,
                    source_route_entries: vec![],
                },
                error_flags: ErrorFlags::none(),
            })))),
        case::deprecated_key_missing(
            &[
                // header: key flag set. Version 0.
                0x20, 0x00,
                // protocol type: ip
                0x08, 0x00,
                // key - missing one byte
                0x12, 0x34, 0x56,
            ],
            Err(Error::incomplete_needed(1))),
        case::deprecated_sequence(
            &[
                // header: sequence flag set. Version 0.
                0x10, 0x00,
                // protocol_type: ip
                0x08, 0x00,
                // sequence,
                0xfe, 0xdc, 0xba, 0x98,
            ],
            Ok((&[] as &[u8], Some(Message{
                header: GreFlags::SEQUENCE_NUMBER.into(),
                protocol_type: 0x0800,
                data: Data::GreDeprecated {
                    checksum: None,
                    offset: None,
                    key: None,
                    sequence_number: Some(4_275_878_552),
                    source_route_entries: vec![],
                },
                error_flags: ErrorFlags::none(),
            })))),
        case::deprecated_sequence_missing(
            &[
                // header: sequence flag set. Version 0.
                0x10, 0x00,
                // protocol_type: ip
                0x08, 0x00,
                // sequence - missing 2 bytes
                0xfe, 0xdc,
            ],
            Err(Error::incomplete_needed(2))),
        case::deprecated_all(
            &[
                // header: all flags set. Version 0.
                0xf8, 0x00,
                // protocol_type: ip
                0x08, 0x00,
                // checksum
                0x12, 0x34,
                // offset
                0x56, 0x78,
                // key
                0x9a, 0xbc, 0xde, 0xf1,
                // sequence number
                0x23, 0x45, 0x67, 0x89,
                // routing entry 1
                0x12, 0x34, 0x56, 0x04,
                // payload
                0xab, 0xcd, 0xef, 0x12,
                // routing entry 2
                0xab, 0xcd, 0xef, 0x08,
                0x12, 0x34, 0x56, 0x78,
                0x9a, 0xbc, 0xde, 0xf1,
                // last routing entry
                0x00, 0x00, 0x00, 0x00,
            ],
            Ok((&[] as &[u8], Some(Message{
                header: Flags::from_bits(63488),
                protocol_type: 0x0800,
                data: Data::GreDeprecated {
                    checksum: Some(4660),
                    offset: Some(22136),
                    key: Some(2_596_069_105),
                    sequence_number: Some(591_751_049),
                    source_route_entries: vec![SourceRouteEntry {
                        address_family: 4660,
                        sre_offset: 86,
                        sre_length: 4,
                        routing_info: vec![0xab, 0xcd, 0xef, 0x12],
                    }, SourceRouteEntry {
                        address_family: 43981,
                        sre_offset: 239,
                        sre_length: 8,
                        routing_info: vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1],
                    }, SourceRouteEntry {
                        address_family: 0,
                        sre_offset: 0,
                        sre_length: 0,
                        routing_info: vec![],
                    }],
                },
                error_flags: ErrorFlags::none(),
            })))),
        case::deprecated_error_recur(
            &[
                // header: checksum and routing flags set, but also recur bits set. Version 0.
                0xc2, 0x00,
                // protocol_type: ip
                0x08, 0x00,
            ],
            Ok((&[] as &[u8], Some(Message {
                header: Flags::from_bits(49664),
                protocol_type: 0x0800,
                data: Data::Empty,
                error_flags: ErrorFlags::RESERVE.into(),
            })))),
        case::deprecated_error_version(
            &[
                // header: checksum, routing, and key flags set. Invalid version (2).
                0xe0, 0x02,
                // protocol type: ip
                0x08, 0x00,
            ],
            Ok((&[] as &[u8], Some(Message {
                header: Flags::from_bits(57346),
                protocol_type: 0x0800,
                data: Data::Empty,
                error_flags: ErrorFlags::VERSION.into(),
            })))),
        case::pptp(
            &[
                // header: key flag set, sequence flag not set. Version 1 and no acknowledgement.
                0x20, 0x01,
                // protocol type: must be 0x880b for PPTP
                0x88, 0x0b,
                // key bytes (payload length (0) and call id)
                0x00, 0x00, 0x00, 0x2f,
            ],
            Ok((&[] as &[u8], Some(Message {
                header: Flags::from_bits(8193),
                protocol_type: 0x880b,
                data: Data::Pptp {
                    payload_length: 0,
                    call_id: 47,
                    sequence_number: None,
                    acknowledgement_number: None,
                    payload: vec![],
                },
                error_flags: ErrorFlags::none(),
            })))),
        case::pptp_missing(
            &[
                // header: key flag set, sequence flag not set. Version 1 and no acknowledgement.
                0x20, 0x01,
                // protocol type: must be 0x880b for PPTP
                0x88, 0x0b,
                // key, 2 bytes missing
                0x00, 0x00,
            ],
            Err(Error::incomplete_needed(2))),
        case::pptp_sequence(
            &[
                // header: key and sequence flag set. Version 1 and no acknowledgement.
                0x30, 0x01,
                // protocol type: must be 0x880b for PPTP
                0x88, 0x0b,
                // key bytes (payload length (8) and call id)
                0x00, 0x08, 0x00, 0x2f,
                // sequence number
                0x00, 0x00, 0x00, 0x01,
                // payload
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1,
            ],
            Ok((&[] as &[u8], Some(Message{
                header: GreFlags::SEQUENCE_NUMBER | GreFlags::KEY | GreFlags::VERSION_PPTP,
                protocol_type: 0x880b,
                data: Data::Pptp {
                    payload_length: 8,
                    call_id: 47,
                    sequence_number: Some(1),
                    acknowledgement_number: None,
                    payload: vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1],
                },
            error_flags: ErrorFlags::none(),
            })))),
        case::pptp_sequence_missing_payload(
            &[
                // header: key and sequence flag set. Version 1 and no acknowledgement.
                0x30, 0x01,
                // protocol type: must be 0x880b for PPTP
                0x88, 0x0b,
                // key bytes (payload length (8) and call id)
                0x00, 0x08, 0x00, 0x2f,
                // sequence number
                0x00, 0x00, 0x00, 0x01,
                // missing payload
            ],
            Err(Error::incomplete_needed(8))),
        case::pptp_acknowledgement(
            &[
                // header: key flag set, sequence flag not set. Version 1 and acknowledgement flag set.
                0x20, 0x81,
                // protocol type: must be 0x880b for PPTP
                0x88, 0x0b,
                // key (payload length (0) and call id)
                0x00, 0x00, 0x00, 0x2f,
                // acknowledgement
                0x12, 0x34, 0x56, 0x78,
            ],
            Ok((&[] as &[u8], Some(Message{
                header: GreFlags::KEY | GreFlags::ACKNOWLEDGEMENT | GreFlags::VERSION_PPTP,
                protocol_type: 0x880b,
                data: Data::Pptp {
                    payload_length: 0,
                    call_id: 47,
                    sequence_number: None,
                    acknowledgement_number: Some(305_419_896),
                    payload: vec![],
                },
                error_flags: ErrorFlags::none(),
                })))),
        case::pptp_acknowledgement_missing(
            &[
                // header: key flag set, sequence flag not set. Version 1 and acknowledgement flag set.
                0x20, 0x81,
                // protocol type: must be 0x880b for PPTP
                0x88, 0x0b,
                // key (payload length (0) and call id)
                0x00, 0x00, 0x00, 0x2f,
                // acknowledgement missing 1 byte
                0x12, 0x34, 0x78,
            ],
            Err(Error::incomplete_needed(1))),
        case::pptp_all(
            &[
                // header: key and sequence flag set. Version 1 and acknowledgement flag set.
                0x30, 0x81,
                // protocol type: must be 0x880b for PPTP
                0x88, 0x0b,
                // key (payload length (4) and call id
                0x00, 0x04, 0x00, 0xff,
                // sequence number
                0x01, 0x02, 0x03, 0x04,
                // acknowledgement number
                0x05, 0x06, 0x07, 0x08,
                // payload
                0x09, 0x0a, 0x0b, 0x0c,
            ],
            Ok((&[] as &[u8], Some(Message{
                header: GreFlags::KEY | GreFlags::SEQUENCE_NUMBER | GreFlags::ACKNOWLEDGEMENT | GreFlags::VERSION_PPTP,
                protocol_type: 0x880b,
                data: Data::Pptp {
                    payload_length: 4,
                    call_id: 255,
                    sequence_number: Some(16_909_060),
                    acknowledgement_number: Some(84_281_096),
                    payload: vec![0x09, 0x0a, 0x0b, 0x0c],
                },
                error_flags: ErrorFlags::none(),
            })))),
    )]
    fn test_parse(input: &[u8], expected: Result<(&[u8], Option<Message>)>) {
        let gre = Gre {};
        assert_eq!(gre.parse(input, Direction::Unknown), expected);
    }

    #[rstest(
        input,
        expected,
        case::empty(b"", Status::Incomplete),
        case::hello_world(b"hello world", Status::Unrecognized),
        case::basic_valid(
            &[
                // gre_flags: no checksum
                0x00,
                // version: must be zero
                0x00,
                // protocol type (ip)
                0x08, 0x00,
            ],
            Status::Recognized
        ),
        case::basic_invalid(
            &[
                // gre_flags: no checksum
                0x00,
                // version: non-zero (error)
                0x02,
                // protocol type (ip)
                0x88, 0xbe,
                // checksum: garbage
                0xab, 0xcd,
                0xff, 0xff,
            ],
            Status::Unrecognized
        )
    )]
    fn test_probe(input: &[u8], expected: Status) {
        let gre = Gre {};

        assert_eq!(gre.probe(input, Direction::Unknown), expected)
    }
}
