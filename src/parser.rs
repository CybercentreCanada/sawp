use crate::error::Result;
use crate::protocol::Protocol;

pub trait Parse: Protocol {
    /// Parse a chunk of bytes into the protocol's Message type.
    ///
    /// Returns a tuple containing the remaining unparsed data and the parsed message.
    fn parse(input: &[u8]) -> Result<(&[u8], Self::Message)>;
}
