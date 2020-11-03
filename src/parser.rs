use crate::error::Result;
use crate::protocol::Protocol;

pub trait Parse: Protocol {
    /// Parse a chunk of bytes into the protocol's Message type.
    ///
    /// Returns a tuple containing the remaining unparsed data and optionally the parsed message, if it was found.
    fn parse<'a>(&'a self, input: &'a [u8]) -> Result<(&'a [u8], Option<Self::Message>)>;
}
