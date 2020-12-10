use crate::error::Result;
use crate::protocol::Protocol;

/// Destination of the input byte stream.
#[derive(Debug, PartialEq)]
pub enum Direction {
    /// Message is destined to the client
    ToClient,
    /// Message is destined to the server
    ToServer,
    /// Direction is not known
    Unknown,
}

pub trait Parse<'a>: Protocol<'a> {
    /// Parse a chunk of bytes into the protocol's Message type.
    ///
    /// `direction` may be used by some parser implementations if it influences
    /// parsing. Otherwise, it can be ignored.
    ///
    /// Returns a tuple containing the remaining unparsed data and optionally
    /// the parsed message, if it was found.
    fn parse(
        &self,
        input: &'a [u8],
        direction: Direction,
    ) -> Result<(&'a [u8], Option<Self::Message>)>;
}
